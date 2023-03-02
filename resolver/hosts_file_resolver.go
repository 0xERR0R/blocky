package resolver

import (
	"context"
	"fmt"
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
)

type HostsFileResolver struct {
	NextResolver
	HostsFilePath  string
	hosts          []HostsFileEntry
	ttl            uint32
	refreshPeriod  time.Duration
	filterLoopback bool
}

type HostsFileEntry = parsers.HostsFileEntry

func (r *HostsFileResolver) handleReverseDNS(request *model.Request) *model.Response {
	question := request.Req.Question[0]
	if question.Qtype == dns.TypePTR {
		response := new(dns.Msg)
		response.SetReply(request.Req)

		for _, host := range r.hosts {
			raddr, _ := dns.ReverseAddr(host.IP.String())

			if raddr == question.Name {
				ptr := new(dns.PTR)
				ptr.Ptr = dns.Fqdn(host.Name)
				ptr.Hdr = util.CreateHeader(question, r.ttl)
				response.Answer = append(response.Answer, ptr)

				for _, alias := range host.Aliases {
					ptrAlias := new(dns.PTR)
					ptrAlias.Ptr = dns.Fqdn(alias)
					ptrAlias.Hdr = util.CreateHeader(question, r.ttl)
					response.Answer = append(response.Answer, ptrAlias)
				}

				return &model.Response{Res: response, RType: model.ResponseTypeHOSTSFILE, Reason: "HOSTS FILE"}
			}
		}
	}

	return nil
}

func (r *HostsFileResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := log.WithPrefix(request.Log, hostsFileResolverLogger)

	if r.HostsFilePath == "" {
		return r.next.Resolve(request)
	}

	reverseResp := r.handleReverseDNS(request)
	if reverseResp != nil {
		return reverseResp, nil
	}

	if len(r.hosts) != 0 {
		response := new(dns.Msg)
		response.SetReply(request.Req)

		question := request.Req.Question[0]
		domain := util.ExtractDomain(question)

		for _, host := range r.hosts {
			response.Answer = append(response.Answer, r.processHostEntry(host, domain, question)...)
		}

		if len(response.Answer) > 0 {
			logger.WithFields(logrus.Fields{
				"answer": util.AnswerToString(response.Answer),
				"domain": domain,
			}).Debugf("returning hosts file entry")

			return &model.Response{Res: response, RType: model.ResponseTypeHOSTSFILE, Reason: "HOSTS FILE"}, nil
		}
	}

	logger.WithField("resolver", Name(r.next)).Trace("go to next resolver")

	return r.next.Resolve(request)
}

func (r *HostsFileResolver) processHostEntry(
	host HostsFileEntry, domain string, question dns.Question,
) (result []dns.RR) {
	if host.Name == domain {
		if isSupportedType(host.IP, question) {
			rr, _ := util.CreateAnswerFromQuestion(question, host.IP, r.ttl)
			result = append(result, rr)
		}
	}

	for _, alias := range host.Aliases {
		if alias == domain {
			if isSupportedType(host.IP, question) {
				rr, _ := util.CreateAnswerFromQuestion(question, host.IP, r.ttl)
				result = append(result, rr)
			}
		}
	}

	return
}

func (r *HostsFileResolver) Configuration() (result []string) {
	if r.HostsFilePath == "" || len(r.hosts) == 0 {
		return configDisabled
	}

	result = append(result, fmt.Sprintf("file path: %s", r.HostsFilePath))
	result = append(result, fmt.Sprintf("TTL: %d", r.ttl))
	result = append(result, fmt.Sprintf("refresh period: %s", r.refreshPeriod.String()))
	result = append(result, fmt.Sprintf("filter loopback addresses: %t", r.filterLoopback))

	return
}

func NewHostsFileResolver(cfg config.HostsFileConfig) *HostsFileResolver {
	r := HostsFileResolver{
		HostsFilePath:  cfg.Filepath,
		ttl:            uint32(time.Duration(cfg.HostsTTL).Seconds()),
		refreshPeriod:  time.Duration(cfg.RefreshPeriod),
		filterLoopback: cfg.FilterLoopback,
	}

	if err := r.parseHostsFile(context.Background()); err != nil {
		logger := log.PrefixedLog(hostsFileResolverLogger)
		logger.Warnf("hosts file resolving is disabled: %s", err)

		r.HostsFilePath = "" // don't try parsing the file again
	} else {
		go r.periodicUpdate()
	}

	return &r
}

func (r *HostsFileResolver) parseHostsFile(ctx context.Context) error {
	const (
		maxErrorsPerFile = 5
		memReleaseFactor = 2
	)

	if r.HostsFilePath == "" {
		return nil
	}

	f, err := os.Open(r.HostsFilePath)
	if err != nil {
		return err
	}
	defer f.Close()

	// reduce initial capacity so we don't waste memory if there are less entries than before
	capacity := len(r.hosts) / memReleaseFactor
	newHosts := make([]HostsFileEntry, 0, capacity)

	p := parsers.AllowErrors(parsers.HostsFile(f), maxErrorsPerFile)
	p.OnErr(func(err error) {
		log.PrefixedLog(hostsFileResolverLogger).Warnf("error parsing %s: %s, trying to continue", r.HostsFilePath, err)
	})

	err = parsers.ForEach[*HostsFileEntry](ctx, p, func(entry *HostsFileEntry) error {
		if len(entry.Interface) != 0 {
			// Ignore entries with a specific interface: we don't restrict what clients/interfaces we serve entries to,
			// so this avoids returning entries that can't be accessed by the client.
			return nil
		}

		// Ignore loopback, if so configured
		if r.filterLoopback && (entry.IP.IsLoopback() || entry.Name == "localhost") {
			return nil
		}

		newHosts = append(newHosts, *entry)

		return nil
	})
	if err != nil {
		return fmt.Errorf("error parsing %s: %w", r.HostsFilePath, err) // err is parsers.ErrTooManyErrors
	}

	r.hosts = newHosts

	return nil
}

func (r *HostsFileResolver) periodicUpdate() {
	if r.refreshPeriod > 0 {
		ticker := time.NewTicker(r.refreshPeriod)
		defer ticker.Stop()

		for {
			<-ticker.C

			logger := log.PrefixedLog(hostsFileResolverLogger)
			logger.WithField("file", r.HostsFilePath).Debug("refreshing hosts file")

			util.LogOnError("can't refresh hosts file: ", r.parseHostsFile(context.Background()))
		}
	}
}
