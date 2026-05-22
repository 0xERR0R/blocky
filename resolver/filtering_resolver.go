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
		removeIPv6Hints(resp.Res)
	}

	return resp, nil
}

// removeIPv6Hints strips the ipv6hint SvcParam from any HTTPS/SVCB record in the response.
// The records are owned by the current request (freshly produced upstream or unpacked from
// cache), so they are modified in place.
//
// Modifying a signed RRset invalidates its DNSSEC signatures, so when a hint is actually
// removed the AD bit is cleared and the now-invalid RRSIGs covering the modified RRsets are
// dropped, to avoid serving DNSSEC-inconsistent data (mirrors the DNS64 resolver behavior).
func removeIPv6Hints(msg *dns.Msg) {
	modified := false

	for _, rr := range msg.Answer {
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
			if kv.Key() == dns.SVCB_IPV6HINT {
				modified = true

				continue
			}

			filtered = append(filtered, kv)
		}

		*values = filtered
	}

	if !modified {
		return
	}

	msg.AuthenticatedData = false
	msg.Answer = removeSVCBSignatures(msg.Answer)
}

// removeSVCBSignatures returns the answers with any RRSIG covering HTTPS or SVCB records removed.
func removeSVCBSignatures(answers []dns.RR) []dns.RR {
	filtered := make([]dns.RR, 0, len(answers))

	for _, rr := range answers {
		if sig, ok := rr.(*dns.RRSIG); ok &&
			(sig.TypeCovered == dns.TypeHTTPS || sig.TypeCovered == dns.TypeSVCB) {
			continue
		}

		filtered = append(filtered, rr)
	}

	return filtered
}
