package resolver

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
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
	HostsFilePath string
	hosts         []host
	ttl           uint32
	refreshPeriod time.Duration
}

func (r *HostsFileResolver) handleReverseDNS(request *model.Request) *model.Response {
	question := request.Req.Question[0]
	if question.Qtype == dns.TypePTR {
		response := new(dns.Msg)
		response.SetReply(request.Req)

		for _, host := range r.hosts {
			raddr, _ := dns.ReverseAddr(host.IP.String())

			if raddr == question.Name {
				ptr := new(dns.PTR)
				ptr.Ptr = dns.Fqdn(host.Hostname)
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
	logger := withPrefix(request.Log, hostsFileResolverLogger)

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

func (r *HostsFileResolver) processHostEntry(host host, domain string, question dns.Question) (result []dns.RR) {
	if host.Hostname == domain {
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
	if r.HostsFilePath != "" && len(r.hosts) != 0 {
		result = append(result, fmt.Sprintf("hosts file path: %s", r.HostsFilePath))
		result = append(result, fmt.Sprintf("hosts TTL: %d", r.ttl))
		result = append(result, fmt.Sprintf("hosts refresh period: %s", r.refreshPeriod.String()))
	} else {
		result = []string{"deactivated"}
	}

	return
}

func NewHostsFileResolver(cfg config.HostsFileConfig) ChainedResolver {
	r := HostsFileResolver{
		HostsFilePath: cfg.Filepath,
		ttl:           uint32(time.Duration(cfg.HostsTTL).Seconds()),
		refreshPeriod: time.Duration(cfg.RefreshPeriod),
	}

	if err := r.parseHostsFile(); err != nil {
		logger := logger(hostsFileResolverLogger)
		logger.Warnf("cannot parse hosts file: %s, hosts file resolving is disabled", r.HostsFilePath)
		r.HostsFilePath = ""
	} else {
		go r.periodicUpdate()
	}

	return &r
}

type host struct {
	IP       net.IP
	Hostname string
	Aliases  []string
}

func (r *HostsFileResolver) parseHostsFile() error {
	const minColumnCount = 2

	if r.HostsFilePath == "" {
		return nil
	}

	buf, err := os.ReadFile(r.HostsFilePath)
	if err != nil {
		return err
	}

	newHosts := make([]host, 0)

	for _, line := range strings.Split(string(buf), "\n") {
		trimmed := strings.TrimSpace(line)

		if len(trimmed) == 0 || trimmed[0] == '#' {
			// Skip empty and commented lines
			continue
		}

		// Find comment symbol at the end of the line
		var fields []string

		end := strings.IndexRune(trimmed, '#')

		if end == -1 {
			fields = strings.Fields(trimmed)
		} else {
			fields = strings.Fields(trimmed[:end])
		}

		if len(fields) < minColumnCount {
			// Skip invalid entry
			continue
		}

		if net.ParseIP(fields[0]) == nil {
			// Skip invalid IP address
			continue
		}

		var h host
		h.IP = net.ParseIP(fields[0])
		h.Hostname = fields[1]

		if len(fields) > minColumnCount {
			for i := 2; i < len(fields); i++ {
				h.Aliases = append(h.Aliases, fields[i])
			}
		}

		newHosts = append(newHosts, h)
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

			logger := logger(hostsFileResolverLogger)
			logger.WithField("file", r.HostsFilePath).Debug("refreshing hosts file")

			util.LogOnError("can't refresh hosts file: ", r.parseHostsFile())
		}
	}
}
