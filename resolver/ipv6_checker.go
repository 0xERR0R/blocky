package resolver

import "github.com/miekg/dns"

// IPv6Checker can drop all AAAA query (empty ANSWER with NOERROR)
type IPv6Checker struct {
	NextResolver
	disableAAAA bool
}

func (r *IPv6Checker) Resolve(request *Request) (*Response, error) {
	if r.disableAAAA && request.Req.Question[0].Qtype == dns.TypeAAAA {
		response := new(dns.Msg)
		response.SetRcode(request.Req, dns.RcodeSuccess)

		return &Response{Res: response, RType: RESOLVED}, nil
	}

	return r.next.Resolve(request)
}

func (r *IPv6Checker) Configuration() (result []string) {
	if r.disableAAAA {
		result = append(result, "drop AAAA")
	} else {
		result = append(result, "accept AAAA")
	}

	return
}

func NewIPv6Checker(disable bool) ChainedResolver {
	return &IPv6Checker{disableAAAA: disable}
}
