package resolver

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/lists/parsers"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	hostsFileResolverLogger = "hosts_file_resolver"

	// reduce initial capacity so we don't waste memory if there are less entries than before
	memReleaseFactor = 2
)

type HostsFileResolver struct {
	NextResolver
	cfg   config.HostsFileConfig
	hosts splitHostsFileData
}

type HostsFileEntry = parsers.HostsFileEntry

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
	logger := log.WithPrefix(request.Log, hostsFileResolverLogger)

	if r.cfg.Filepath == "" {
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
		logger.WithFields(logrus.Fields{
			"answer": util.AnswerToString(response.Answer),
			"domain": domain,
		}).Debugf("returning hosts file entry")

		return &model.Response{Res: response, RType: model.ResponseTypeHOSTSFILE, Reason: "HOSTS FILE"}, nil
	}

	logger.WithField("resolver", Name(r.next)).Trace("go to next resolver")

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

func (r *HostsFileResolver) Configuration() (result []string) {
	if r.cfg.Filepath == "" || r.hosts.isEmpty() {
		return configDisabled
	}

	result = append(result, fmt.Sprintf("file path: %s", r.cfg.Filepath))
	result = append(result, fmt.Sprintf("TTL: %d", r.cfg.HostsTTL.SecondsU32()))
	result = append(result, fmt.Sprintf("refresh period: %s", r.cfg.RefreshPeriod))
	result = append(result, fmt.Sprintf("filter loopback addresses: %t", r.cfg.FilterLoopback))

	return
}

func NewHostsFileResolver(cfg config.HostsFileConfig) *HostsFileResolver {
	r := HostsFileResolver{
		cfg: cfg,
	}

	if err := r.parseHostsFile(context.Background()); err != nil {
		logger := log.PrefixedLog(hostsFileResolverLogger)
		logger.Warnf("hosts file resolving is disabled: %s", err)

		r.cfg.Filepath = "" // don't try parsing the file again
	} else {
		go r.periodicUpdate()
	}

	return &r
}

func (r *HostsFileResolver) parseHostsFile(ctx context.Context) error {
	const maxErrorsPerFile = 5

	if r.cfg.Filepath == "" {
		return nil
	}

	f, err := os.Open(r.cfg.Filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	newHosts := newSplitHostsDataWithSameCapacity(r.hosts)

	p := parsers.AllowErrors(parsers.HostsFile(f), maxErrorsPerFile)
	p.OnErr(func(err error) {
		log.PrefixedLog(hostsFileResolverLogger).Warnf("error parsing %s: %s, trying to continue", r.cfg.Filepath, err)
	})

	err = parsers.ForEach[*HostsFileEntry](ctx, p, func(entry *HostsFileEntry) error {
		if len(entry.Interface) != 0 {
			// Ignore entries with a specific interface: we don't restrict what clients/interfaces we serve entries to,
			// so this avoids returning entries that can't be accessed by the client.
			return nil
		}

		// Ignore loopback, if so configured
		if r.cfg.FilterLoopback && (entry.IP.IsLoopback() || entry.Name == "localhost") {
			return nil
		}

		newHosts.add(entry)

		return nil
	})
	if err != nil {
		return fmt.Errorf("error parsing %s: %w", r.cfg.Filepath, err) // err is parsers.ErrTooManyErrors
	}

	r.hosts = newHosts

	return nil
}

func (r *HostsFileResolver) periodicUpdate() {
	if r.cfg.RefreshPeriod.Cast() > 0 {
		ticker := time.NewTicker(r.cfg.RefreshPeriod.Cast())
		defer ticker.Stop()

		for {
			<-ticker.C

			logger := log.PrefixedLog(hostsFileResolverLogger)
			logger.WithField("file", r.cfg.Filepath).Debug("refreshing hosts file")

			util.LogOnError("can't refresh hosts file: ", r.parseHostsFile(context.Background()))
		}
	}
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
	return d.v4.isEmpty() && d.v6.isEmpty()
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

func (d hostsFileData) isEmpty() bool {
	return len(d.hosts) == 0 && len(d.aliases) == 0
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
