package resolver

import (
	"context"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

// FilteringResolver filters DNS queries (for example can drop all AAAA query)
// returns empty ANSWER with NOERROR
type FilteringResolver struct {
	configurable[*config.Filtering]
	NextResolver
	typed
}

func NewFilteringResolver(cfg config.Filtering) *FilteringResolver {
	return &FilteringResolver{
		configurable: withConfig(&cfg),
		typed:        withType("filtering"),
	}
}

func (r *FilteringResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	qType := request.Req.Question[0].Qtype
	if r.cfg.QueryTypes.Contains(dns.Type(qType)) {
		return model.NewResponseWithRcode(request, dns.RcodeSuccess, model.ResponseTypeFILTERED, ""), nil
	}

	resp, err := r.next.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}

	// When AAAA lookups are filtered, also drop IPv6 hints from HTTPS/SVCB answers so that
	// clients can't reach the IPv6 endpoints advertised via SvcParams (RFC 9460).
	if resp != nil && resp.Res != nil && r.cfg.QueryTypes.Contains(dns.Type(dns.TypeAAAA)) {
		removeIPv6Hints(resp.Res.Answer)
	}

	return resp, nil
}

// removeIPv6Hints strips the ipv6hint SvcParam from any HTTPS/SVCB record in the given
// answer set. The records are owned by the current request (freshly produced upstream or
// unpacked from cache), so they are modified in place.
func removeIPv6Hints(answers []dns.RR) {
	for _, rr := range answers {
		var values *[]dns.SVCBKeyValue

		switch v := rr.(type) {
		case *dns.HTTPS:
			values = &v.Value
		case *dns.SVCB:
			values = &v.Value
		default:
			continue
		}

		filtered := make([]dns.SVCBKeyValue, 0, len(*values))

		for _, kv := range *values {
			if kv.Key() != dns.SVCB_IPV6HINT {
				filtered = append(filtered, kv)
			}
		}

		*values = filtered
	}
}
