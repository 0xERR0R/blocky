package resolver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

// FilteringResolver filters DNS queries (for example can drop all AAAA query)
// returns empty ANSWER with NOERROR
type FilteringResolver struct {
	NextResolver
	queryTypes config.QTypeSet
}

func (r *FilteringResolver) Resolve(request *model.Request) (*model.Response, error) {
	qType := request.Req.Question[0].Qtype
	if r.queryTypes.Contains(dns.Type(qType)) {
		response := new(dns.Msg)
		response.SetRcode(request.Req, dns.RcodeSuccess)

		return &model.Response{Res: response, RType: model.ResponseTypeFILTERED}, nil
	}

	return r.next.Resolve(request)
}

func (r *FilteringResolver) Configuration() (result []string) {
	qTypes := make([]string, len(r.queryTypes))
	ix := 0

	for qType := range r.queryTypes {
		qTypes[ix] = qType.String()
		ix++
	}

	sort.Strings(qTypes)

	result = append(result, fmt.Sprintf("filtering query Types: '%v'", strings.Join(qTypes, ", ")))

	return
}

func NewFilteringResolver(cfg config.FilteringConfig) ChainedResolver {
	return &FilteringResolver{
		queryTypes: cfg.QueryTypes,
	}
}
