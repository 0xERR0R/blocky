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
	mapping map[string]net.IP
}

func NewCustomDNSResolver(cfg config.CustomDNSConfig) ChainedResolver {
	m := make(map[string]net.IP)
	for url, ip := range cfg.Mapping {
		m[strings.ToLower(url)] = ip
	}

	return &CustomDNSResolver{mapping: m}
}

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

func (r *CustomDNSResolver) Resolve(request *Request) (*Response, error) {
	logger := withPrefix(request.Log, "custom_dns_resolver")

	if len(r.mapping) > 0 {
		for _, question := range request.Req.Question {
			domain := util.ExtractDomain(question)
			for len(domain) > 0 {
				ip, found := r.mapping[domain]
				if found {
					response := new(dns.Msg)
					response.SetReply(request.Req)

					if isSupportedType(ip, question) {
						rr := util.CreateAnswerFromQuestion(question, ip, customDNSTTL)

						response.Answer = append(response.Answer, rr)

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
	}

	logger.WithField("resolver", Name(r.next)).Trace("go to next resolver")

	return r.next.Resolve(request)
}
