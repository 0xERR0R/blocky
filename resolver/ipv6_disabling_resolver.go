package resolver

import (
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

// IPv6DisablingResolver can drop all AAAA query (empty ANSWER with NOERROR)
type IPv6DisablingResolver struct {
	NextResolver
	disableAAAA bool
}

func (r *IPv6DisablingResolver) Resolve(request *model.Request) (*model.Response, error) {
	if r.disableAAAA && request.Req.Question[0].Qtype == dns.TypeAAAA {
		response := new(dns.Msg)
		response.SetRcode(request.Req, dns.RcodeSuccess)

		return &model.Response{Res: response, RType: model.ResponseTypeRESOLVED}, nil
	}

	return r.next.Resolve(request)
}

func (r *IPv6DisablingResolver) Configuration() (result []string) {
	if r.disableAAAA {
		result = append(result, "drop AAAA")
	} else {
		result = append(result, "accept AAAA")
	}

	return
}

func NewIPv6Checker(disable bool) ChainedResolver {
	return &IPv6DisablingResolver{disableAAAA: disable}
}
