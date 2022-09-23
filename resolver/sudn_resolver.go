package resolver

import (
	"fmt"
	"net"
	"strings"

	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

const (
	sudnTest      = "test."
	sudnInvalid   = "invalid."
	sudnLocalhost = "localhost."
	mdnsLocal     = "local."
)

func sudnArpaSlice() []string {
	return []string{
		"10.in-addr.arpa.",
		"21.172.in-addr.arpa.",
		"26.172.in-addr.arpa.",
		"16.172.in-addr.arpa.",
		"22.172.in-addr.arpa.",
		"27.172.in-addr.arpa.",
		"17.172.in-addr.arpa.",
		"30.172.in-addr.arpa.",
		"28.172.in-addr.arpa.",
		"18.172.in-addr.arpa.",
		"23.172.in-addr.arpa.",
		"29.172.in-addr.arpa.",
		"19.172.in-addr.arpa.",
		"24.172.in-addr.arpa.",
		"31.172.in-addr.arpa.",
		"20.172.in-addr.arpa.",
		"25.172.in-addr.arpa.",
		"168.192.in-addr.arpa.",
	}
}

type defaultIPs struct {
	loopbackV4 net.IP
	loopbackV6 net.IP
}

type SpecialUseDomainNamesResolver struct {
	NextResolver
	defaults *defaultIPs
}

func NewSpecialUseDomainNamesResolver() ChainedResolver {
	return &SpecialUseDomainNamesResolver{
		defaults: &defaultIPs{
			loopbackV4: net.ParseIP("127.0.0.1"),
			loopbackV6: net.IPv6loopback,
		},
	}
}

func (r *SpecialUseDomainNamesResolver) Resolve(request *model.Request) (*model.Response, error) {
	// RFC 6761 - negative
	if r.isSpecial(request, sudnArpaSlice()...) ||
		r.isSpecial(request, sudnInvalid) ||
		r.isSpecial(request, sudnTest) {
		return r.negativeResponse(request)
	}
	// RFC 6761 - switched
	if r.isSpecial(request, sudnLocalhost) {
		return r.responseSwitch(request, sudnLocalhost, r.defaults.loopbackV4, r.defaults.loopbackV6)
	}

	// RFC 6762 - negative
	if r.isSpecial(request, mdnsLocal) {
		return r.negativeResponse(request)
	}

	return r.next.Resolve(request)
}

// RFC 6761 & 6762 are always active
func (r *SpecialUseDomainNamesResolver) Configuration() []string {
	return []string{}
}

func (r *SpecialUseDomainNamesResolver) isSpecial(request *model.Request, names ...string) bool {
	domainFromQuestion := request.Req.Question[0].Name
	for _, n := range names {
		if domainFromQuestion == n ||
			strings.HasSuffix(domainFromQuestion, fmt.Sprintf(".%s", n)) {
			return true
		}
	}

	return false
}

func (r *SpecialUseDomainNamesResolver) responseSwitch(request *model.Request,
	name string, ipV4, ipV6 net.IP) (*model.Response, error) {
	qtype := request.Req.Question[0].Qtype
	switch qtype {
	case dns.TypeA:
		return r.positiveResponse(request, name, dns.TypeA, ipV4)
	case dns.TypeAAAA:
		return r.positiveResponse(request, name, dns.TypeAAAA, ipV6)
	default:
		return r.negativeResponse(request)
	}
}

func (r *SpecialUseDomainNamesResolver) positiveResponse(request *model.Request,
	name string, rtype uint16, ip net.IP) (*model.Response, error) {
	response := newResponseMsg(request)
	response.Rcode = dns.RcodeSuccess

	hdr := dns.RR_Header{
		Name:   name,
		Rrtype: rtype,
		Class:  dns.ClassINET,
		Ttl:    0,
	}

	if rtype != dns.TypeA && rtype != dns.TypeAAAA {
		return nil, fmt.Errorf("invalid response type")
	}

	var rr dns.RR
	if rtype == dns.TypeA {
		rr = &dns.A{
			A:   ip,
			Hdr: hdr,
		}
	} else {
		rr = &dns.AAAA{
			AAAA: ip,
			Hdr:  hdr,
		}
	}

	response.Answer = []dns.RR{rr}

	return r.returnResponseModel(response)
}

func (r *SpecialUseDomainNamesResolver) negativeResponse(request *model.Request) (*model.Response, error) {
	response := newResponseMsg(request)
	response.Rcode = dns.RcodeNameError

	return r.returnResponseModel(response)
}

func (r *SpecialUseDomainNamesResolver) returnResponseModel(response *dns.Msg) (*model.Response, error) {
	return returnResponseModel(response, model.ResponseTypeSPECIAL, "Special-Use Domain Name")
}
