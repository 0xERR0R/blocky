package resolver

import (
	"net"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// CustomDNSResolver resolves passed domain name to ip address defined in domain-IP map
type CustomDNSResolver struct {
	configurable[*config.CustomDNSConfig]
	NextResolver
	typed

	mapping          map[string][]net.IP
	reverseAddresses map[string][]string
}

// NewCustomDNSResolver creates new resolver instance
func NewCustomDNSResolver(cfg config.CustomDNSConfig) *CustomDNSResolver {
	m := make(map[string][]net.IP, len(cfg.Mapping.HostIPs))
	reverse := make(map[string][]string, len(cfg.Mapping.HostIPs))

	for url, ips := range cfg.Mapping.HostIPs {
		m[strings.ToLower(url)] = ips

		for _, ip := range ips {
			r, _ := dns.ReverseAddr(ip.String())
			reverse[r] = append(reverse[r], url)
		}
	}

	return &CustomDNSResolver{
		configurable: withConfig(&cfg),
		typed:        withType("custom_dns"),

		mapping:          m,
		reverseAddresses: reverse,
	}
}

func isSupportedType(ip net.IP, question dns.Question) bool {
	return (ip.To4() != nil && question.Qtype == dns.TypeA) ||
		(strings.Contains(ip.String(), ":") && question.Qtype == dns.TypeAAAA)
}

func (r *CustomDNSResolver) handleReverseDNS(request *model.Request) *model.Response {
	question := request.Req.Question[0]
	if question.Qtype == dns.TypePTR {
		urls, found := r.reverseAddresses[question.Name]
		if found {
			response := new(dns.Msg)
			response.SetReply(request.Req)

			for _, url := range urls {
				h := util.CreateHeader(question, r.cfg.CustomTTL.SecondsU32())
				ptr := new(dns.PTR)
				ptr.Ptr = dns.Fqdn(url)
				ptr.Hdr = h
				response.Answer = append(response.Answer, ptr)
			}

			return &model.Response{Res: response, RType: model.ResponseTypeCUSTOMDNS, Reason: "CUSTOM DNS"}
		}
	}

	return nil
}

func (r *CustomDNSResolver) processRequest(request *model.Request) *model.Response {
	logger := log.WithPrefix(request.Log, "custom_dns_resolver")

	response := new(dns.Msg)
	response.SetReply(request.Req)

	question := request.Req.Question[0]
	domain := util.ExtractDomain(question)

	for len(domain) > 0 {
		ips, found := r.mapping[domain]
		if found {
			for _, ip := range ips {
				if isSupportedType(ip, question) {
					rr, _ := util.CreateAnswerFromQuestion(question, ip, r.cfg.CustomTTL.SecondsU32())
					response.Answer = append(response.Answer, rr)
				}
			}

			if len(response.Answer) > 0 {
				logger.WithFields(logrus.Fields{
					"answer": util.AnswerToString(response.Answer),
					"domain": domain,
				}).Debugf("returning custom dns entry")

				return &model.Response{Res: response, RType: model.ResponseTypeCUSTOMDNS, Reason: "CUSTOM DNS"}
			}

			// Mapping exists for this domain, but for another type
			if !r.cfg.FilterUnmappedTypes {
				// go to next resolver
				break
			}

			// return NOERROR with empty result
			return &model.Response{Res: response, RType: model.ResponseTypeCUSTOMDNS, Reason: "CUSTOM DNS"}
		}

		if i := strings.Index(domain, "."); i >= 0 {
			domain = domain[i+1:]
		} else {
			break
		}
	}

	return nil
}

// Resolve uses internal mapping to resolve the query
func (r *CustomDNSResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := log.WithPrefix(request.Log, "custom_dns_resolver")

	reverseResp := r.handleReverseDNS(request)
	if reverseResp != nil {
		return reverseResp, nil
	}

	if len(r.mapping) > 0 {
		resp := r.processRequest(request)
		if resp != nil {
			return resp, nil
		}
	}

	logger.WithField("resolver", Name(r.next)).Trace("go to next resolver")

	return r.next.Resolve(request)
}
