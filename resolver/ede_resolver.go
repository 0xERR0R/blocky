package resolver

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

// A EdeResolver is responsible for adding the reason for the response as EDNS0 option
type EdeResolver struct {
	configurable[*config.EDE]
	NextResolver
	typed
}

// NewEdeResolver creates new resolver instance which adds the reason for
// the response as EDNS0 option to the response if it is enabled in the configuration
func NewEdeResolver(cfg config.EDE) *EdeResolver {
	return &EdeResolver{
		configurable: withConfig(&cfg),
		typed:        withType("extended_error_code"),
	}
}

// Resolve adds the reason as EDNS0 option to the response of the next resolver
// if it is enabled in the configuration
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

// addExtraReasoning adds the reason for the response as EDNS0 option
func (r *EdeResolver) addExtraReasoning(res *model.Response) {
	infocode := res.RType.ToExtendedErrorCode()

	if infocode == dns.ExtendedErrorCodeOther {
		// dns.ExtendedErrorCodeOther seams broken in some clients
		return
	}

	edeOption := new(dns.EDNS0_EDE)
	edeOption.InfoCode = infocode
	edeOption.ExtraText = res.Reason

	util.SetEdns0Option(res.Res, edeOption)
}
