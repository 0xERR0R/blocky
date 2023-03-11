package resolver

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

type EdeResolver struct {
	NextResolver

	cfg config.EdeConfig
}

func NewEdeResolver(cfg config.EdeConfig) ChainedResolver {
	return &EdeResolver{
		cfg: cfg,
	}
}

func (r *EdeResolver) Resolve(request *model.Request) (*model.Response, error) {
	if !r.cfg.Enable {
		return r.next.Resolve(request)
	}

	resp, err := r.next.Resolve(request)
	if err != nil {
		return nil, err
	}

	r.addExtraReasoning(resp)

	return resp, nil
}

func (r *EdeResolver) Configuration() (result []string) {
	if !r.cfg.Enable {
		return configDisabled
	}

	return configEnabled
}

func (r *EdeResolver) addExtraReasoning(res *model.Response) {
	infocode := res.RType.ToExtendedErrorCode()

	if infocode == dns.ExtendedErrorCodeOther {
		// dns.ExtendedErrorCodeOther seams broken in some clients
		return
	}

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{
		InfoCode:  infocode,
		ExtraText: res.Reason,
	})
	res.Res.Extra = append(res.Res.Extra, opt)
}
