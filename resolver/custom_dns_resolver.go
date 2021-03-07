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
	mapping map[string][]net.IP
}

// NewCustomDNSResolver creates new resolver instance
func NewCustomDNSResolver(cfg config.CustomDNSConfig) ChainedResolver {
	m := make(map[string][]net.IP)
	for url, ips := range cfg.Mapping.HostIPs {
		m[strings.ToLower(url)] = ips
	}

	return &CustomDNSResolver{mapping: m}
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

// Resolve uses internal mapping to resolve the query
func (r *CustomDNSResolver) Resolve(request *Request) (*Response, error) {
	logger := withPrefix(request.Log, "custom_dns_resolver")

	if len(r.mapping) > 0 {
		question := request.Req.Question[0]
		domain := util.ExtractDomain(question)

		for len(domain) > 0 {
			ips, found := r.mapping[domain]
			if found {
				response := new(dns.Msg)
				response.SetReply(request.Req)

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
