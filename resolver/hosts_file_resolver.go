package resolver

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const hostsDNSTTL = 3600

type HostsFileResolver struct {
	NextResolver
	HostsFilePath string
	parsed        bool
	hosts         []host
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
				ptr.Hdr = util.CreateHeader(question, hostsDNSTTL)
				response.Answer = append(response.Answer, ptr)

				return &model.Response{Res: response, RType: model.ResponseTypeHOSTSFILE, Reason: "HOSTS FILE"}
			}
		}
	}

	return nil
}

func (r *HostsFileResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := withPrefix(request.Log, "hosts_file_resolver")

	if r.HostsFilePath == "" {
		logger.WithField("resolver", Name(r.next)).Trace("go to next resolver")
		return r.next.Resolve(request)
	}

	if !r.parsed {
		err := r.parseHostsFile()
		if err != nil {
			return nil, err
		}

		r.parsed = true
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
			if host.Hostname == domain {
				if isSupportedType(host.IP, question) {
					rr, _ := util.CreateAnswerFromQuestion(question, host.IP, hostsDNSTTL)
					response.Answer = append(response.Answer, rr)
				}
			}

			for _, alias := range host.Aliases {
				if alias == domain {
					if isSupportedType(host.IP, question) {
						rr, _ := util.CreateAnswerFromQuestion(question, host.IP, hostsDNSTTL)
						response.Answer = append(response.Answer, rr)
					}
				}
			}
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

func (r *HostsFileResolver) Configuration() (result []string) {
	if r.HostsFilePath != "" {
		result = append(result, fmt.Sprintf("hosts file path: %s", r.HostsFilePath))
	} else {
		result = []string{"deactivated"}
	}

	return
}

func NewHostsFileResolver(filepath string) ChainedResolver {
	return &HostsFileResolver{HostsFilePath: filepath}
}

type host struct {
	IP       net.IP
	Hostname string
	Aliases  []string
}

func (r *HostsFileResolver) parseHostsFile() error {
	if r.HostsFilePath == "" {
		return nil
	}

	buf, err := os.ReadFile(r.HostsFilePath)
	if err != nil {
		return err
	}

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

		if len(fields) < 2 {
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

		if len(fields) > 2 {
			for i := 2; i < len(fields); i++ {
				h.Aliases = append(h.Aliases, fields[i])
			}
		}

		r.hosts = append(r.hosts, h)
	}

	return nil
}
