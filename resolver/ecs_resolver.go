package resolver

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

type EcsResolver struct {
	configurable[*config.EcsConfig]
	NextResolver
	typed
}

func NewEcsResolver(cfg config.EcsConfig) ChainedResolver {
	return &EcsResolver{
		configurable: withConfig(&cfg),
		typed:        withType("extended_client_subnet"),
	}
}

func (r *EcsResolver) Resolve(request *model.Request) (*model.Response, error) {
	if r.cfg.IsEnabled() {
		if !r.setClientIP(request) {
			r.appendSubnet(request)
		}
	}

	return r.next.Resolve(request)
}

func (r *EcsResolver) setClientIP(request *model.Request) bool {
	edns := request.Req.IsEdns0()
	if edns == nil {
		return false
	}

	result := false

	newOpts := []dns.EDNS0{}

	for _, o := range edns.Option {
		switch so := o.(type) {
		case *dns.EDNS0_SUBNET:
			// v4 and mask
			if (so.Family == 1 && so.SourceNetmask == 32) ||
				// v6 and unmasked
				(so.Family == 2 && so.SourceNetmask == 128) {
				request.ClientIP = so.Address
			}

			if r.cfg.ForwardEcs {
				newOpts = append(newOpts, o)
			}

			result = true
		default:
			newOpts = append(newOpts, o)
		}
	}

	edns.Option = newOpts

	return result
}

func (r *EcsResolver) appendSubnet(request *model.Request) {
	e := new(dns.EDNS0_SUBNET)
	e.Code = dns.EDNS0SUBNET
	e.SourceScope = 0

	if ip := request.ClientIP.To4(); ip != nil && r.cfg.IPv4Mask > 0 {
		e.Family = 1
		e.SourceNetmask = r.cfg.IPv4Mask
		e.Address = ip
		r.appendOption(request, e)
	} else if request.ClientIP.To16() != nil && r.cfg.IPv6Mask > 0 {
		e.Family = 2
		e.SourceNetmask = r.cfg.IPv6Mask
		e.Address = ip
		r.appendOption(request, e)
	}
}

func (r *EcsResolver) appendOption(request *model.Request, opt dns.EDNS0) {
	if edns := request.Req.IsEdns0(); edns != nil {
		edns.Option = append(edns.Option, opt)
	}

	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.Option = append(o.Option, opt)

	request.Req.Extra = append(request.Req.Extra, o)
}
