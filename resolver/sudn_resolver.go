package resolver

import (
	"context"
	"net"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

type sudnHandler = func(request *model.Request, cfg *config.SUDN) *model.Response

//nolint:gochecknoglobals
var (
	loopbackV4 = net.ParseIP("127.0.0.1")
	loopbackV6 = net.IPv6loopback

	// See Wikipedia for an up-to-date reference:
	// https://en.wikipedia.org/wiki/Special-use_domain_name
	sudnHandlers = map[string]sudnHandler{
		// RFC 6761
		// https://www.rfc-editor.org/rfc/rfc6761
		//
		// Section 6.1
		"10.in-addr.arpa.":      sudnNXDomain,
		"21.172.in-addr.arpa.":  sudnNXDomain,
		"26.172.in-addr.arpa.":  sudnNXDomain,
		"16.172.in-addr.arpa.":  sudnNXDomain,
		"22.172.in-addr.arpa.":  sudnNXDomain,
		"27.172.in-addr.arpa.":  sudnNXDomain,
		"17.172.in-addr.arpa.":  sudnNXDomain,
		"30.172.in-addr.arpa.":  sudnNXDomain,
		"28.172.in-addr.arpa.":  sudnNXDomain,
		"18.172.in-addr.arpa.":  sudnNXDomain,
		"23.172.in-addr.arpa.":  sudnNXDomain,
		"29.172.in-addr.arpa.":  sudnNXDomain,
		"19.172.in-addr.arpa.":  sudnNXDomain,
		"24.172.in-addr.arpa.":  sudnNXDomain,
		"31.172.in-addr.arpa.":  sudnNXDomain,
		"20.172.in-addr.arpa.":  sudnNXDomain,
		"25.172.in-addr.arpa.":  sudnNXDomain,
		"168.192.in-addr.arpa.": sudnNXDomain,
		// Section 6.2
		"test.": sudnNXDomain,
		// Section 6.3
		"localhost.": sudnLocalhost,
		// Section 6.4
		"invalid.": sudnNXDomain,
		// Section 6.5
		"example.":     nil,
		"example.com.": nil,
		"example.net.": nil,
		"example.org.": nil,

		// RFC 6762
		// https://www.rfc-editor.org/rfc/rfc6762
		//
		// mDNS is not implemented, so just return NXDOMAIN
		//
		// Section 3
		"local.": sudnNXDomain,
		// Section 12
		"254.169.in-addr.arpa.": sudnNXDomain, // also section 4
		"8.e.f.ip6.arpa.":       sudnNXDomain,
		"9.e.f.ip6.arpa.":       sudnNXDomain,
		"a.e.f.ip6.arpa.":       sudnNXDomain,
		"b.e.f.ip6.arpa.":       sudnNXDomain,
		// Appendix G
		"intranet.": sudnRFC6762AppendixG,
		"internal.": sudnRFC6762AppendixG,
		"private.":  sudnRFC6762AppendixG,
		"corp.":     sudnRFC6762AppendixG,
		"home.":     sudnRFC6762AppendixG,
		"lan.":      sudnRFC6762AppendixG,

		// RFC 7686
		// https://www.rfc-editor.org/rfc/rfc7686
		"onion.": sudnNXDomain,

		// RFC 8375
		// https://www.rfc-editor.org/rfc/rfc8375
		//
		// Section 4
		"home.arpa.": sudnHomeArpa,
	}
)

type SpecialUseDomainNamesResolver struct {
	NextResolver
	typed
	configurable[*config.SUDN]
}

func NewSpecialUseDomainNamesResolver(cfg config.SUDN) *SpecialUseDomainNamesResolver {
	return &SpecialUseDomainNamesResolver{
		typed:        withType("special_use_domains"),
		configurable: withConfig(&cfg),
	}
}

func (r *SpecialUseDomainNamesResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	handler := r.handler(request)
	if handler != nil {
		resp := handler(request, r.cfg)
		if resp != nil {
			return resp, nil
		}
	}

	return r.next.Resolve(ctx, request)
}

func (r *SpecialUseDomainNamesResolver) handler(request *model.Request) sudnHandler {
	q := request.Req.Question[0]
	domain := q.Name

	for {
		handler, ok := sudnHandlers[domain]
		if ok {
			return handler
		}

		_, after, ok := strings.Cut(domain, ".")
		if !ok {
			return nil
		}

		domain = after
	}
}

func newSUDNResponse(response *model.Request, rcode int) *model.Response {
	return newResponse(response, rcode, model.ResponseTypeSPECIAL, "Special-Use Domain Name")
}

func sudnNXDomain(request *model.Request, _ *config.SUDN) *model.Response {
	return newSUDNResponse(request, dns.RcodeNameError)
}

func sudnLocalhost(request *model.Request, cfg *config.SUDN) *model.Response {
	q := request.Req.Question[0]

	var rr dns.RR

	switch q.Qtype {
	case dns.TypeA:
		rr = &dns.A{A: loopbackV4}
	case dns.TypeAAAA:
		rr = &dns.AAAA{AAAA: loopbackV6}
	default:
		return sudnNXDomain(request, cfg)
	}

	*rr.Header() = dns.RR_Header{
		Name:   q.Name,
		Rrtype: q.Qtype,
		Class:  dns.ClassINET,
		Ttl:    0,
	}

	response := newSUDNResponse(request, dns.RcodeSuccess)
	response.Res.Answer = []dns.RR{rr}

	return response
}

func sudnRFC6762AppendixG(request *model.Request, cfg *config.SUDN) *model.Response {
	if !cfg.RFC6762AppendixG {
		return nil
	}

	return sudnNXDomain(request, cfg)
}

func sudnHomeArpa(request *model.Request, cfg *config.SUDN) *model.Response {
	if request.Req.Question[0].Qtype == dns.TypeDS {
		// DS queries must be forwarded
		return nil
	}

	return sudnNXDomain(request, cfg)
}
