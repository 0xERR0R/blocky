package resolver

import (
	"context"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

// A EDEResolver is responsible for adding the reason for the response as EDNS0 option
type EDEResolver struct {
	configurable[*config.EDE]
	NextResolver
	typed
}

// NewEDEResolver creates new resolver instance which adds the reason for
// the response as EDNS0 option to the response if it is enabled in the configuration
func NewEDEResolver(cfg config.EDE) *EDEResolver {
	return &EDEResolver{
		configurable: withConfig(&cfg),
		typed:        withType("extended_error_code"),
	}
}

// Resolve adds the reason as EDNS0 option to the response of the next resolver
// if it is enabled in the configuration
func (r *EDEResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	if !r.cfg.Enable {
		return r.next.Resolve(ctx, request)
	}

	resp, err := r.next.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}

	r.addExtraReasoning(resp)

	return resp, nil
}

// addExtraReasoning adds the reason for the response as EDNS0 option
func (r *EDEResolver) addExtraReasoning(res *model.Response) {
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
