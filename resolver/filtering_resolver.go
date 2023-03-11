package resolver

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// FilteringResolver filters DNS queries (for example can drop all AAAA query)
// returns empty ANSWER with NOERROR
type FilteringResolver struct {
	NextResolver

	cfg config.FilteringConfig
}

func NewFilteringResolver(cfg config.FilteringConfig) ChainedResolver {
	return &FilteringResolver{
		cfg: cfg,
	}
}

// IsEnabled implements `config.ValueLogger`.
func (r *FilteringResolver) IsEnabled() bool {
	return r.cfg.IsEnabled()
}

// LogValues implements `config.ValueLogger`.
func (r *FilteringResolver) LogValues(logger *logrus.Entry) {
	r.cfg.LogValues(logger)
}

func (r *FilteringResolver) Resolve(request *model.Request) (*model.Response, error) {
	qType := request.Req.Question[0].Qtype
	if r.cfg.QueryTypes.Contains(dns.Type(qType)) {
		response := new(dns.Msg)
		response.SetRcode(request.Req, dns.RcodeSuccess)

		return &model.Response{Res: response, RType: model.ResponseTypeFILTERED}, nil
	}

	return r.next.Resolve(request)
}
