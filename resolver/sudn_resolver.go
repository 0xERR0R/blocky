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

type SpecialUseDomainNamesResolver struct {
	NextResolver
}

func NewSpecialUseDomainNamesResolver() ChainedResolver {
	return &SpecialUseDomainNamesResolver{}
}

func (r *SpecialUseDomainNamesResolver) Resolve(request *model.Request) (*model.Response, error) {
	if r.isSpecial(request, sudnArpaSlice()...) ||
		r.isSpecial(request, sudnInvalid) ||
		r.isSpecial(request, sudnTest) {
		return r.negativeResponse(request)
	} else if r.isSpecial(request, sudnLocalhost) {
		qtype := request.Req.Question[0].Qtype
		fmt.Println("QType:", qtype)
		switch qtype {
		case dns.TypeA:
			return r.loopbackResponseA(request)
		case dns.TypeAAAA:
			return r.loopbackResponseAAAA(request)
		default:
			return r.negativeResponse(request)
		}
	}

	return r.next.Resolve(request)
}

// Special-Use Domain Names (RFC 6761) always active
func (r *SpecialUseDomainNamesResolver) Configuration() []string {
	return []string{}
}

func (r *SpecialUseDomainNamesResolver) negativeResponse(request *model.Request) (*model.Response, error) {
	response := r.newResponseMsg(request)
	response.Rcode = dns.RcodeNameError

	return r.returnResponseModel(response)
}

func (r *SpecialUseDomainNamesResolver) loopbackResponseA(request *model.Request) (*model.Response, error) {
	response := r.newResponseMsg(request)
	response.Rcode = dns.RcodeSuccess

	rr := new(dns.A)
	rr.Hdr = dns.RR_Header{
		Name:   sudnLocalhost,
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    0,
	}

	rr.A = net.ParseIP("127.0.0.1")

	response.Answer = []dns.RR{rr}

	return r.returnResponseModel(response)
}

func (r *SpecialUseDomainNamesResolver) loopbackResponseAAAA(request *model.Request) (*model.Response, error) {
	response := r.newResponseMsg(request)
	response.Rcode = dns.RcodeSuccess

	rr := new(dns.AAAA)
	rr.Hdr = dns.RR_Header{
		Name:   sudnLocalhost,
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    0,
	}

	rr.AAAA = net.ParseIP("::1")

	response.Answer = []dns.RR{rr}

	return r.returnResponseModel(response)
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

func (r *SpecialUseDomainNamesResolver) newResponseMsg(request *model.Request) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request.Req)

	return response
}

func (r *SpecialUseDomainNamesResolver) returnResponseModel(response *dns.Msg) (*model.Response, error) {
	return &model.Response{
		Res:    response,
		RType:  model.ResponseTypeSPECIAL,
		Reason: "Special-Use Domain Name",
	}, nil
}
