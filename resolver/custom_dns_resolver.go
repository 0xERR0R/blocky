package resolver

import (
	"context"
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
	configurable[*config.CustomDNS]
	NextResolver
	typed

	mapping          map[string][]dns.RR
	reverseAddresses map[string][]string
}

// NewCustomDNSResolver creates new resolver instance
func NewCustomDNSResolver(cfg config.CustomDNS) *CustomDNSResolver {
	m := make(map[string][]dns.RR, len(cfg.Mapping.Entries))
	reverse := make(map[string][]string, len(cfg.Mapping.Entries))

	for url, entries := range cfg.Mapping.Entries {
		m[strings.ToLower(url)] = entries

		for _, entry := range entries {
			_, isA := entry.(*dns.A)
			_, isAAAA := entry.(*dns.AAAA)

			if !isA && !isAAAA {
				continue
			}

			r, _ := dns.ReverseAddr(entry.String())
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

func (r *CustomDNSResolver) processRequest(ctx context.Context, request *model.Request) (*model.Response, error) {
	logger := log.WithPrefix(request.Log, "custom_dns_resolver")

	response := new(dns.Msg)
	response.SetReply(request.Req)

	question := request.Req.Question[0]
	domain := util.ExtractDomain(question)

	for len(domain) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, found := r.mapping[domain]
		if found {
			for _, entry := range entries {
				switch v := entry.(type) {
				case *dns.A:
					result, err := r.processIP(v.A, question)
					if err != nil {
						return nil, err
					}
					response.Answer = append(response.Answer, result...)
				case *dns.AAAA:
					result, err := r.processIP(v.AAAA, question)
					if err != nil {
						return nil, err
					}
					response.Answer = append(response.Answer, result...)
				case *dns.CNAME:
					result, err := r.processCNAME(ctx, request, *v, question)
					if err != nil {
						return nil, err
					}

					response.Answer = append(response.Answer, result...)
				default:
				}
			}

			if len(response.Answer) > 0 {
				logger.WithFields(logrus.Fields{
					"answer": util.AnswerToString(response.Answer),
					"domain": domain,
				}).Debugf("returning custom dns entry")

				return &model.Response{Res: response, RType: model.ResponseTypeCUSTOMDNS, Reason: "CUSTOM DNS"}, nil
			}

			// Mapping exists for this domain, but for another type
			if !r.cfg.FilterUnmappedTypes {
				// go to next resolver
				break
			}

			// return NOERROR with empty result
			return &model.Response{Res: response, RType: model.ResponseTypeCUSTOMDNS, Reason: "CUSTOM DNS"}, nil
		}

		if i := strings.Index(domain, "."); i >= 0 {
			domain = domain[i+1:]
		} else {
			break
		}
	}

	logger.WithField("next_resolver", Name(r.next)).Trace("go to next resolver")
	forwardResponse, err := r.next.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}

	return forwardResponse, nil
}

// Resolve uses internal mapping to resolve the query
func (r *CustomDNSResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	reverseResp := r.handleReverseDNS(request)
	if reverseResp != nil {
		return reverseResp, nil
	}

	resp, err := r.processRequest(ctx, request)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (r *CustomDNSResolver) processIP(ip net.IP, question dns.Question) (result []dns.RR, err error) {
	result = make([]dns.RR, 0)

	if isSupportedType(ip, question) {
		rr, err := util.CreateAnswerFromQuestion(question, ip, r.cfg.CustomTTL.SecondsU32())
		if err != nil {
			return nil, err
		}
		result = append(result, rr)
	}

	return result, nil
}

func (r *CustomDNSResolver) processCNAME(ctx context.Context, request *model.Request, targetCname dns.CNAME, question dns.Question) (result []dns.RR, err error) {
	cname := new(dns.CNAME)
	cname.Hdr = dns.RR_Header{Class: dns.ClassINET, Ttl: r.cfg.CustomTTL.SecondsU32(), Rrtype: dns.TypeCNAME, Name: question.Name}
	cname.Target = dns.Fqdn(targetCname.Target)
	result = append(result, cname)

	targetWithoutDot := strings.TrimSuffix(targetCname.Target, ".")

	// Resolve target recursively
	targetResp, err := r.processRequest(ctx, newRequestWithClientID(targetWithoutDot, dns.Type(dns.TypeA), request.ClientIP.String(), request.RequestClientID))
	if err != nil {
		return nil, err
	}
	result = append(result, targetResp.Res.Answer...)

	// Resolve ipv6 target recursively
	targetResp, err = r.processRequest(ctx, newRequestWithClientID(targetWithoutDot, dns.Type(dns.TypeAAAA), request.ClientIP.String(), request.RequestClientID))
	if err != nil {
		return nil, err
	}
	result = append(result, targetResp.Res.Answer...)

	return result, nil
}
