package resolver

import (
	"context"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"net"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/lists"
	"github.com/0xERR0R/blocky/lists/parsers"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/ThinkChaos/parcour"
	"github.com/ThinkChaos/parcour/jobgroup"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	// reduce initial capacity so we don't waste memory if there are less entries than before
	memReleaseFactor = 2

	producersBuffCap = 1000
)

type HostsFileEntry = parsers.HostsFileEntry

type HostsFileResolver struct {
	configurable[*config.HostsFile]
	NextResolver
	typed

	// hosts index is synchronized with Sources in config.HostsFile,
	// allowing partial update
	hosts      splitHostsFileDataSlice
	downloader lists.FileDownloader
}

func NewHostsFileResolver(ctx context.Context,
	cfg config.HostsFile,
	bootstrap *Bootstrap,
) (*HostsFileResolver, error) {
	r := HostsFileResolver{
		configurable: withConfig(&cfg),
		typed:        withType("hosts_file"),

		downloader: lists.NewDownloader(cfg.Loading.Downloads, bootstrap.NewHTTPTransport()),
	}
	r.hosts.data.Store(new([]splitHostsFileData))

	if cfg.WatchUpdates && len(cfg.Sources) > 0 {
		var hasFileSource bool
		for i := range cfg.Sources {
			if cfg.Sources[i].Type == config.BytesSourceTypeFile {
				hasFileSource = true
				break
			}
		}
		if hasFileSource {
			go r.watchUpdates(ctx)
		}
	}

	err := cfg.Loading.StartPeriodicRefresh(ctx, r.loadSources, func(err error) {
		_, logger := r.log(ctx)
		logger.WithError(err).Errorf("could not load hosts files")
	})
	if err != nil {
		return nil, err
	}

	return &r, nil
}

// LogConfig implements `config.Configurable`.
func (r *HostsFileResolver) LogConfig(logger *logrus.Entry) {
	r.cfg.LogConfig(logger)

	logger.Infof("cache entries = %d", r.hosts.len())
}

func (r *HostsFileResolver) handleReverseDNS(request *model.Request) *model.Response {
	question := request.Req.Question[0]
	if question.Qtype != dns.TypePTR {
		return nil
	}

	questionIP, err := util.ParseIPFromArpaAddr(question.Name)
	if err != nil {
		// ignore the parse error, and pass the request down the chain
		return nil
	}

	if r.cfg.FilterLoopback && questionIP.IsLoopback() {
		// skip the search: we won't find anything
		return nil
	}

	// search only in the hosts with an IP version that matches the question
	isIP6 := questionIP.To4() == nil

	for _, hosts := range *r.hosts.data.Load() {
		hostsData := hosts.v4
		if isIP6 {
			hostsData = hosts.v6
		}
		for host, hostData := range hostsData.hosts {
			if hostData.IP.Equal(questionIP) {
				response := new(dns.Msg)
				response.SetReply(request.Req)

				ptr := new(dns.PTR)
				ptr.Ptr = dns.Fqdn(host)
				ptr.Hdr = util.CreateHeader(question, r.cfg.HostsTTL.SecondsU32())
				response.Answer = append(response.Answer, ptr)

				for _, alias := range hostData.Aliases {
					ptrAlias := new(dns.PTR)
					ptrAlias.Ptr = dns.Fqdn(alias)
					ptrAlias.Hdr = ptr.Hdr
					response.Answer = append(response.Answer, ptrAlias)
				}

				return &model.Response{Res: response, RType: model.ResponseTypeHOSTSFILE, Reason: "HOSTS FILE"}
			}
		}
	}

	return nil
}

func (r *HostsFileResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	if !r.IsEnabled() {
		return r.next.Resolve(ctx, request)
	}

	ctx, logger := r.log(ctx)

	reverseResp := r.handleReverseDNS(request)
	if reverseResp != nil {
		return reverseResp, nil
	}

	question := request.Req.Question[0]
	domain := util.ExtractDomain(question)

	response := r.resolve(request.Req, question, domain)
	if response != nil {
		logger.WithFields(logrus.Fields{
			"answer": util.AnswerToString(response.Answer),
			"domain": util.Obfuscate(domain),
		}).Debugf("returning hosts file entry")

		return &model.Response{Res: response, RType: model.ResponseTypeHOSTSFILE, Reason: "HOSTS FILE"}, nil
	}

	logger.WithField("next_resolver", Name(r.next)).Trace("go to next resolver")

	return r.next.Resolve(ctx, request)
}

func (r *HostsFileResolver) resolve(req *dns.Msg, question dns.Question, domain string) *dns.Msg {
	ip := r.hosts.getIP(dns.Type(question.Qtype), domain)
	if ip == nil {
		return nil
	}

	rr, _ := util.CreateAnswerFromQuestion(question, ip, r.cfg.HostsTTL.SecondsU32())

	response := new(dns.Msg)
	response.SetReply(req)
	response.Answer = []dns.RR{rr}

	return response
}

// reloadSource is concurrent safe
func (r *HostsFileResolver) reloadSource(ctx context.Context, sourceID int) error {
	if !r.IsEnabled() {
		return nil
	}
	source := r.cfg.Sources[sourceID]

	ctx, logger := r.log(ctx)
	logger.WithField("source_id", strconv.Itoa(sourceID)).
		WithField("path", source.String()).
		Debug("reloading hosts file")

	locInfo := fmt.Sprintf("item #%d", sourceID)

	opener, err := lists.NewSourceOpener(locInfo, source, r.downloader)
	if err != nil {
		return err
	}

	entries, err := r.parseFile(ctx, opener)
	if err != nil {
		return fmt.Errorf("error parsing %s: %w", opener, err) // err is parsers.ErrTooManyErrors
	}

	var hosts splitHostsFileData
	for i := range entries {
		hosts.add(&entries[i])
	}
	r.hosts.update(sourceID, hosts)

	return nil
}

// loadSources is concurrent safe
func (r *HostsFileResolver) loadSources(ctx context.Context) error {
	if !r.IsEnabled() {
		return nil
	}

	ctx, logger := r.log(ctx)

	logger.Debug("loading hosts files")

	//nolint:ineffassign,staticcheck,wastedassign // keep `ctx :=` so if we use ctx in the future, we use the correct one
	consumersGrp, ctx := jobgroup.WithContext(ctx)
	defer consumersGrp.Close()

	producersGrp := jobgroup.WithMaxConcurrency(consumersGrp, r.cfg.Loading.Concurrency)
	defer producersGrp.Close()

	type ParseResult struct {
		SourceID int
		Entries  []HostsFileEntry
	}

	producers := parcour.NewProducersWithBuffer[ParseResult](producersGrp, consumersGrp, producersBuffCap)
	defer producers.Close()

	for i, source := range r.cfg.Sources {
		i, source := i, source

		producers.GoProduce(func(ctx context.Context, hostsChan chan<- ParseResult) error {
			locInfo := fmt.Sprintf("item #%d", i)

			opener, err := lists.NewSourceOpener(locInfo, source, r.downloader)
			if err != nil {
				return err
			}

			entries, err := r.parseFile(ctx, opener)
			if err != nil {
				return fmt.Errorf("error parsing %s: %w", opener, err) // err is parsers.ErrTooManyErrors
			}

			hostsChan <- ParseResult{
				SourceID: i,
				Entries:  entries,
			}

			return nil
		})
	}

	newHosts := make([]splitHostsFileData, len(r.cfg.Sources))

	producers.GoConsume(func(ctx context.Context, ch <-chan ParseResult) error {
		for result := range ch {
			var hosts splitHostsFileData
			for i := range result.Entries {
				hosts.add(&result.Entries[i])
			}
			newHosts[result.SourceID] = hosts
		}

		return nil
	})

	err := producers.Wait()
	if err != nil {
		return err
	}

	// replace the whole data store atomically
	r.hosts.data.Store(&newHosts)

	return nil
}

func (r *HostsFileResolver) watchUpdates(ctx context.Context) {
	watcher, err := fsnotify.NewWatcher()
	_, logger := r.log(ctx)
	if err != nil {
		logger.WithError(err).Errorf("cannot create hosts file watcher, disabling")
		return
	}

	defer func() {
		err := watcher.Close()
		if err != nil {
			util.LogOnError(ctx, "failed to close hosts file watcher", err)
		}
		logger.Info("hosts file watcher closed")
	}()

	for i, src := range r.cfg.Sources {
		if src.Type != config.BytesSourceTypeFile {
			continue
		}
		err = watcher.Add(src.From)
		if err != nil {
			logger.WithError(err).WithField("path", src.String()).WithField("id", strconv.Itoa(i)).
				Error("failed to watch hosts file, hosts file watcher is disabled")
			return
		}
	}

	// update event IDs, unique
	chanUpdate := make(chan int32, 32)
	defer close(chanUpdate)
	updateEventID := &atomic.Int32{} // the last update event ID

	go func() {
		for id := range chanUpdate {
			// file editors like vim, will generate multiple events in one update,
			// so we wait for some time to ensure there are (likely) no following operations
			time.Sleep(time.Millisecond * 250)
			if updateEventID.Load() != id {
				// if id has changed, there must be one new operation in channel
				// ignore current one and continue checking the next one
				continue
			}
			// the event is probably the last one in one update, load file content
			logger.WithField("source", "file_watcher").
				Debug("refreshing hosts file")
			util.LogOnError(ctx, "can't refresh hosts file on update: ", r.loadSources(ctx))
		}
	}()

	logger.Debug("hosts file watcher started")
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			isWrite := event.Op&fsnotify.Write != 0
			isCreate := event.Op&fsnotify.Create != 0
			isRemove := event.Op&fsnotify.Remove != 0
			isRename := event.Op&fsnotify.Rename != 0
			if isWrite || isCreate || isRemove || isRename {
				chanUpdate <- updateEventID.Add(1)
			}
		case err, ok := <-watcher.Errors:
			util.LogOnError(ctx, "error watching hosts file", err)
			if !ok {
				return
			}
		}
	}
}

func (r *HostsFileResolver) parseFile(
	ctx context.Context, opener lists.SourceOpener,
) (ret []HostsFileEntry, err error) {
	reader, err := opener.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	p := parsers.AllowErrors(parsers.HostsFile(reader), r.cfg.Loading.MaxErrorsPerSource)
	p.OnErr(func(err error) {
		_, logger := r.log(ctx)

		logger.Warnf("error parsing %s: %s, trying to continue", opener, err)
	})

	_ = parsers.ForEach[*HostsFileEntry](ctx, p, func(entry *HostsFileEntry) error {
		if len(entry.Interface) != 0 {
			// Ignore entries with a specific interface: we don't restrict what clients/interfaces we serve entries to,
			// so this avoids returning entries that can't be accessed by the client.
			return nil
		}

		// Ignore loopback, if so configured
		if r.cfg.FilterLoopback && (entry.IP.IsLoopback() || entry.Name == "localhost") {
			return nil
		}

		ret = append(ret, *entry)

		return nil
	})
	return ret, nil
}

// stores hosts file data for IP versions separately
//
// Makes finding an IP for a question faster.
// Especially reverse lookups where we have to iterate through
// all the known hosts.
type splitHostsFileData struct {
	v4 hostsFileData
	v6 hostsFileData
}

func newSplitHostsDataWithSameCapacity(other splitHostsFileData) splitHostsFileData {
	return splitHostsFileData{
		v4: newHostsDataWithSameCapacity(other.v4),
		v6: newHostsDataWithSameCapacity(other.v6),
	}
}

func (d splitHostsFileData) isEmpty() bool {
	return d.len() == 0
}

func (d splitHostsFileData) len() int {
	return d.v4.len() + d.v6.len()
}

func (d splitHostsFileData) getIP(qType dns.Type, domain string) net.IP {
	switch uint16(qType) {
	case dns.TypeA:
		return d.v4.getIP(domain)
	case dns.TypeAAAA:
		return d.v6.getIP(domain)
	}

	return nil
}

func (d splitHostsFileData) add(entry *parsers.HostsFileEntry) {
	if entry.IP.To4() != nil {
		d.v4.add(entry)
	} else {
		d.v6.add(entry)
	}
}

// splitHostsFileDataSlice is a copy-on-write container allows
// lock-free concurrent read & write on multiple hosts data sources.
type splitHostsFileDataSlice struct {
	data atomic.Pointer[[]splitHostsFileData]
}

// update will panic if sourceID does not exist before updating
func (d *splitHostsFileDataSlice) update(sourceID int, entry splitHostsFileData) {
	newData := slices.Clone(*d.data.Load())
	newData[sourceID] = entry
	d.data.Store(&newData)
}

func (d *splitHostsFileDataSlice) isEmpty() bool {
	for _, source := range *d.data.Load() {
		if !source.isEmpty() {
			return false
		}
	}
	return true
}

func (d *splitHostsFileDataSlice) len() int {
	var sum int
	for _, source := range *d.data.Load() {
		sum += source.len()
	}
	return sum
}

func (d *splitHostsFileDataSlice) getIP(qType dns.Type, domain string) net.IP {
	for _, source := range *d.data.Load() {
		var v net.IP
		switch uint16(qType) {
		case dns.TypeA:
			v = source.v4.getIP(domain)
		case dns.TypeAAAA:
			v = source.v6.getIP(domain)
		}
		if v != nil {
			return v
		}
	}

	return nil
}

type hostsFileData struct {
	hosts   map[string]hostData
	aliases map[string]net.IP
}

type hostData struct {
	IP      net.IP
	Aliases []string
}

func newHostsDataWithSameCapacity(other hostsFileData) hostsFileData {
	return hostsFileData{
		hosts:   make(map[string]hostData, len(other.hosts)/memReleaseFactor),
		aliases: make(map[string]net.IP, len(other.aliases)/memReleaseFactor),
	}
}

func (d hostsFileData) len() int {
	return len(d.hosts) + len(d.aliases)
}

func (d hostsFileData) getIP(hostname string) net.IP {
	if hostData, ok := d.hosts[hostname]; ok {
		return hostData.IP
	}

	if ip, ok := d.aliases[hostname]; ok {
		return ip
	}

	return nil
}

func (d hostsFileData) add(entry *parsers.HostsFileEntry) {
	d.hosts[entry.Name] = hostData{entry.IP, entry.Aliases}

	for _, alias := range entry.Aliases {
		d.aliases[alias] = entry.IP
	}
}
