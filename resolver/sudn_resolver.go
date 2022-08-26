package resolver

import (
	"fmt"
	"strings"

	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
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

type SudnResolver struct {
	NextResolver
}

func NewSudnResolver() ChainedResolver {
	return &SudnResolver{}
}

func (r *SudnResolver) Resolve(request *model.Request) (*model.Response, error) {
	if r.isSpecial(request, sudnArpaSlice()...) ||
		r.isSpecial(request, sudnInvalid) ||
		r.isSpecial(request, sudnTest) {
		return r.negativeResponse()
	}

	return r.next.Resolve(request)
}

func (r *SudnResolver) Configuration() []string {
	return []string{"Special-Use Domain Names (RFC 6761)"}
}

func (r *SudnResolver) negativeResponse() (*model.Response, error) {
	response := new(dns.Msg)
	response.Rcode = dns.RcodeNameError

	return &model.Response{
		Res:    response,
		RType:  model.ResponseTypeSPECIAL,
		Reason: "Special-Use Domain Name",
	}, nil
}

func (r *SudnResolver) isSpecial(request *model.Request, names ...string) bool {
	domainFromQuestion := util.ExtractDomain(request.Req.Question[0])
	for _, n := range names {
		if domainFromQuestion == n ||
			strings.HasSuffix(domainFromQuestion, fmt.Sprintf(".%s", n)) {
			return true
		}
	}

	return false
}
