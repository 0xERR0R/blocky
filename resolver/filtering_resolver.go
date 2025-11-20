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

	return r.next.Resolve(ctx, request)
}
