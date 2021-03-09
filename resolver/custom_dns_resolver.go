package resolver

import (
	"blocky/config"
	"blocky/util"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const customDNSTTL = 60 * 60

// CustomDNSResolver resolves passed domain name to ip address defined in domain-IP map
type CustomDNSResolver struct {
	NextResolver
	mapping          map[string][]net.IP
	reverseAddresses map[string][]string
}

// NewCustomDNSResolver creates new resolver instance
func NewCustomDNSResolver(cfg config.CustomDNSConfig) ChainedResolver {
	m := make(map[string][]net.IP)
	reverse := make(map[string][]string)

	for url, ips := range cfg.Mapping.HostIPs {
		m[strings.ToLower(url)] = ips

		for _, ip := range ips {
			r, _ := dns.ReverseAddr(ip.String())
			reverse[r] = append(reverse[r], url)
		}
	}

	return &CustomDNSResolver{mapping: m, reverseAddresses: reverse}
}

// Configuration returns current resolver configuration
func (r *CustomDNSResolver) Configuration() (result []string) {
	if len(r.mapping) > 0 {
		for key, val := range r.mapping {
			result = append(result, fmt.Sprintf("%s = \"%s\"", key, val))
		}
	} else {
		result = []string{"deactivated"}
	}

	return
}

func isSupportedType(ip net.IP, question dns.Question) bool {
	return (ip.To4() != nil && question.Qtype == dns.TypeA) ||
		(strings.Contains(ip.String(), ":") && question.Qtype == dns.TypeAAAA)
}

func (r *CustomDNSResolver) handleReverseDNS(request *Request) *Response {
	question := request.Req.Question[0]
	if question.Qtype == dns.TypePTR {
		urls, found := r.reverseAddresses[question.Name]
		if found {
			response := new(dns.Msg)
			response.SetReply(request.Req)

			for _, url := range urls {
				h := util.CreateHeader(question, customDNSTTL)
				ptr := new(dns.PTR)
				ptr.Ptr = dns.Fqdn(url)
				ptr.Hdr = h
				response.Answer = append(response.Answer, ptr)
			}

			return &Response{Res: response, RType: CUSTOMDNS, Reason: "CUSTOM DNS"}
		}
	}

	return nil
}

// Resolve uses internal mapping to resolve the query
func (r *CustomDNSResolver) Resolve(request *Request) (*Response, error) {
	logger := withPrefix(request.Log, "custom_dns_resolver")

	reverseResp := r.handleReverseDNS(request)
	if reverseResp != nil {
		return reverseResp, nil
	}

	if len(r.mapping) > 0 {
		response := new(dns.Msg)
		response.SetReply(request.Req)

		question := request.Req.Question[0]
		domain := util.ExtractDomain(question)

		for len(domain) > 0 {
			ips, found := r.mapping[domain]
			if found {
				for _, ip := range ips {
					if isSupportedType(ip, question) {
						rr, _ := util.CreateAnswerFromQuestion(question, ip, customDNSTTL)
						response.Answer = append(response.Answer, rr)
					}
				}

				if len(response.Answer) > 0 {
					logger.WithFields(logrus.Fields{
						"answer": util.AnswerToString(response.Answer),
						"domain": domain,
					}).Debugf("returning custom dns entry")

					return &Response{Res: response, RType: CUSTOMDNS, Reason: "CUSTOM DNS"}, nil
				}

				response.Rcode = dns.RcodeNameError

				return &Response{Res: response, RType: CUSTOMDNS, Reason: "CUSTOM DNS"}, nil
			}

			if i := strings.Index(domain, "."); i >= 0 {
				domain = domain[i+1:]
			} else {
				break
			}
		}
	}

	logger.WithField("resolver", Name(r.next)).Trace("go to next resolver")

	return r.next.Resolve(request)
}
