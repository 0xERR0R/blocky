package resolver

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type createAnswerFunc func(question dns.Question, ip net.IP, ttl uint32) (dns.RR, error)

// CustomDNSResolver resolves passed domain name to ip address defined in domain-IP map
type CustomDNSResolver struct {
	configurable[*config.CustomDNS]
	NextResolver
	typed

	createAnswerFromQuestion createAnswerFunc
	mapping                  config.CustomDNSMapping
	reverseAddresses         map[string][]string
}

// NewCustomDNSResolver creates new resolver instance
func NewCustomDNSResolver(cfg config.CustomDNS) *CustomDNSResolver {
	m := make(config.CustomDNSMapping, len(cfg.Mapping))
	reverse := make(map[string][]string, len(cfg.Mapping))

	for url, entries := range cfg.Mapping {
		m[strings.ToLower(url)] = entries

		for _, entry := range entries {
			a, isA := entry.(*dns.A)

			if isA {
				r, _ := dns.ReverseAddr(a.A.String())
				reverse[r] = append(reverse[r], url)
			}

			aaaa, isAAAA := entry.(*dns.AAAA)

			if isAAAA {
				r, _ := dns.ReverseAddr(aaaa.AAAA.String())
				reverse[r] = append(reverse[r], url)
			}
		}
	}

	return &CustomDNSResolver{
		configurable: withConfig(&cfg),
		typed:        withType("custom_dns"),

		createAnswerFromQuestion: util.CreateAnswerFromQuestion,
		mapping:                  m,
		reverseAddresses:         reverse,
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

func (r *CustomDNSResolver) forwardResponse(
	logger *logrus.Entry,
	ctx context.Context,
	request *model.Request,
) (*model.Response, error) {
	logger.WithField("next_resolver", Name(r.next)).Trace("go to next resolver")

	forwardResponse, err := r.next.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}

	return forwardResponse, nil
}

func (r *CustomDNSResolver) processRequest(
	ctx context.Context,
	request *model.Request,
	resolvedCnames []string,
) (*model.Response, error) {
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
				result, err := r.processDNSEntry(ctx, request, resolvedCnames, question, entry)
				if err != nil {
					return nil, err
				}

				response.Answer = append(response.Answer, result...)
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

	return r.forwardResponse(logger, ctx, request)
}

func (r *CustomDNSResolver) processDNSEntry(
	ctx context.Context,
	request *model.Request,
	resolvedCnames []string,
	question dns.Question,
	entry dns.RR,
) ([]dns.RR, error) {
	switch v := entry.(type) {
	case *dns.A:
		return r.processIP(v.A, question)
	case *dns.AAAA:
		return r.processIP(v.AAAA, question)
	case *dns.CNAME:
		return r.processCNAME(ctx, request, *v, resolvedCnames, question)
	}

	return nil, fmt.Errorf("unsupported customDNS RR type %T", entry)
}

// Resolve uses internal mapping to resolve the query
func (r *CustomDNSResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	reverseResp := r.handleReverseDNS(request)
	if reverseResp != nil {
		return reverseResp, nil
	}

	resp, err := r.processRequest(ctx, request, make([]string, 0, len(r.cfg.Mapping)))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (r *CustomDNSResolver) processIP(ip net.IP, question dns.Question) (result []dns.RR, err error) {
	result = make([]dns.RR, 0)

	if isSupportedType(ip, question) {
		rr, err := r.createAnswerFromQuestion(question, ip, r.cfg.CustomTTL.SecondsU32())
		if err != nil {
			return nil, err
		}

		result = append(result, rr)
	}

	return result, nil
}

func (r *CustomDNSResolver) processCNAME(
	ctx context.Context,
	request *model.Request,
	targetCname dns.CNAME,
	resolvedCnames []string,
	question dns.Question,
) (result []dns.RR, err error) {
	cname := new(dns.CNAME)
	ttl := r.cfg.CustomTTL.SecondsU32()
	cname.Hdr = dns.RR_Header{Class: dns.ClassINET, Ttl: ttl, Rrtype: dns.TypeCNAME, Name: question.Name}
	cname.Target = dns.Fqdn(targetCname.Target)
	result = append(result, cname)

	if question.Qtype == dns.TypeCNAME {
		return result, nil
	}

	targetWithoutDot := strings.TrimSuffix(targetCname.Target, ".")

	if slices.Contains(resolvedCnames, targetWithoutDot) {
		return nil, fmt.Errorf("CNAME loop detected: %v", append(resolvedCnames, targetWithoutDot))
	}

	cnames := resolvedCnames
	cnames = append(cnames, targetWithoutDot)

	clientIP := request.ClientIP.String()
	clientID := request.RequestClientID
	targetRequest := newRequestWithClientID(targetWithoutDot, dns.Type(question.Qtype), clientIP, clientID)

	// resolve the target recursively
	targetResp, err := r.processRequest(ctx, targetRequest, cnames)
	if err != nil {
		return nil, err
	}

	result = append(result, targetResp.Res.Answer...)

	return result, nil
}

func (r *CustomDNSResolver) CreateAnswerFromQuestion(newFunc createAnswerFunc) {
	r.createAnswerFromQuestion = newFunc
}
