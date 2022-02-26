package resolver

import (
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

// IPv6DisablingResolver can drop all AAAA query (empty ANSWER with NOERROR)
type IPv6DisablingResolver struct {
	NextResolver
}

func (r *IPv6DisablingResolver) Resolve(request *model.Request) (*model.Response, error) {
	if request.Req.Question[0].Qtype == dns.TypeAAAA {
		response := new(dns.Msg)
		response.SetRcode(request.Req, dns.RcodeSuccess)

		return &model.Response{Res: response, RType: model.ResponseTypeRESOLVED}, nil
	}

	return r.next.Resolve(request)
}

func (r *IPv6DisablingResolver) Configuration() (result []string) {
	result = append(result, "drop AAAA")
	return
}

func NewIPv6Checker(disableAAAA bool) ChainedResolver {
	if !disableAAAA {
		return nil
	}

	return &IPv6DisablingResolver{}
}
