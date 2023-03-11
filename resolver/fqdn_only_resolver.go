package resolver

import (
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type FqdnOnlyResolver struct {
	NextResolver

	cfg config.FqdnOnlyConfig
}

func NewFqdnOnlyResolver(cfg config.FqdnOnlyConfig) *FqdnOnlyResolver {
	return &FqdnOnlyResolver{
		cfg: cfg,
	}
}

// IsEnabled implements `config.ValueLogger`.
func (r *FqdnOnlyResolver) IsEnabled() bool {
	return r.cfg.IsEnabled()
}

// LogValues implements `config.ValueLogger`.
func (r *FqdnOnlyResolver) LogValues(logger *logrus.Entry) {
	r.cfg.LogValues(logger)
}

func (r *FqdnOnlyResolver) Resolve(request *model.Request) (*model.Response, error) {
	if r.IsEnabled() {
		domainFromQuestion := util.ExtractDomain(request.Req.Question[0])
		if !strings.Contains(domainFromQuestion, ".") {
			response := new(dns.Msg)
			response.Rcode = dns.RcodeNameError

			return &model.Response{Res: response, RType: model.ResponseTypeNOTFQDN, Reason: "NOTFQDN"}, nil
		}
	}

	return r.next.Resolve(request)
}
