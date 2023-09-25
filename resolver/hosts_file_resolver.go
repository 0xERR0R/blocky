package resolver

import (
	"context"
	"fmt"
	"net"

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
	configurable[*config.HostsFileConfig]
	NextResolver
	typed

	hosts      splitHostsFileData
	downloader lists.FileDownloader
}

func NewHostsFileResolver(cfg config.HostsFileConfig, bootstrap *Bootstrap) (*HostsFileResolver, error) {
	r := HostsFileResolver{
		configurable: withConfig(&cfg),
		typed:        withType("hosts_file"),

		downloader: lists.NewDownloader(cfg.Loading.Downloads, bootstrap.NewHTTPTransport()),
	}

	err := cfg.Loading.StartPeriodicRefresh(r.loadSources, func(err error) {
		r.log().WithError(err).Errorf("could not load hosts files")
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
	hostsData := r.hosts.v4
	if questionIP.To4() == nil {
		hostsData = r.hosts.v6
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

	return nil
}

func (r *HostsFileResolver) Resolve(request *model.Request) (*model.Response, error) {
	if !r.IsEnabled() {
		return r.next.Resolve(request)
	}

	reverseResp := r.handleReverseDNS(request)
	if reverseResp != nil {
		return reverseResp, nil
	}

	question := request.Req.Question[0]
	domain := util.ExtractDomain(question)

	response := r.resolve(request.Req, question, domain)
	if response != nil {
		r.log().WithFields(logrus.Fields{
			"answer": util.AnswerToString(response.Answer),
			"domain": domain,
		}).Debugf("returning hosts file entry")

		return &model.Response{Res: response, RType: model.ResponseTypeHOSTSFILE, Reason: "HOSTS FILE"}, nil
	}

	r.log().WithField("resolver", Name(r.next)).Trace("go to next resolver")

	return r.next.Resolve(request)
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

func (r *HostsFileResolver) loadSources(ctx context.Context) error {
	if !r.IsEnabled() {
		return nil
	}

	r.log().Debug("loading hosts files")

	//nolint:ineffassign,staticcheck,wastedassign // keep `ctx :=` so if we use ctx in the future, we use the correct one
	consumersGrp, ctx := jobgroup.WithContext(ctx)
	defer consumersGrp.Close()

	producersGrp := jobgroup.WithMaxConcurrency(consumersGrp, r.cfg.Loading.Concurrency)
	defer producersGrp.Close()

	producers := parcour.NewProducersWithBuffer[*HostsFileEntry](producersGrp, consumersGrp, producersBuffCap)
	defer producers.Close()

	for i, source := range r.cfg.Sources {
		i, source := i, source

		producers.GoProduce(func(ctx context.Context, hostsChan chan<- *HostsFileEntry) error {
			locInfo := fmt.Sprintf("item #%d", i)

			opener, err := lists.NewSourceOpener(locInfo, source, r.downloader)
			if err != nil {
				return err
			}

			err = r.parseFile(ctx, opener, hostsChan)
			if err != nil {
				return fmt.Errorf("error parsing %s: %w", opener, err) // err is parsers.ErrTooManyErrors
			}

			return nil
		})
	}

	newHosts := newSplitHostsDataWithSameCapacity(r.hosts)

	producers.GoConsume(func(ctx context.Context, ch <-chan *HostsFileEntry) error {
		for entry := range ch {
			newHosts.add(entry)
		}

		return nil
	})

	err := producers.Wait()
	if err != nil {
		return err
	}

	r.hosts = newHosts

	return nil
}

func (r *HostsFileResolver) parseFile(
	ctx context.Context, opener lists.SourceOpener, hostsChan chan<- *HostsFileEntry,
) error {
	reader, err := opener.Open()
	if err != nil {
		return err
	}
	defer reader.Close()

	p := parsers.AllowErrors(parsers.HostsFile(reader), r.cfg.Loading.MaxErrorsPerSource)
	p.OnErr(func(err error) {
		r.log().Warnf("error parsing %s: %s, trying to continue", opener, err)
	})

	return parsers.ForEach[*HostsFileEntry](ctx, p, func(entry *HostsFileEntry) error {
		if len(entry.Interface) != 0 {
			// Ignore entries with a specific interface: we don't restrict what clients/interfaces we serve entries to,
			// so this avoids returning entries that can't be accessed by the client.
			return nil
		}

		// Ignore loopback, if so configured
		if r.cfg.FilterLoopback && (entry.IP.IsLoopback() || entry.Name == "localhost") {
			return nil
		}

		hostsChan <- entry

		return nil
	})
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
