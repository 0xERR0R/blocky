package resolver

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

const (
	ecsIpv4Family = 1
	ecsIpv4Mask   = 32
	ecsIpv6Family = 2
	ecsIpv6Mask   = 128
)

// A EcsResolver is responsible for adding the subnet information as EDNS0 option
type EcsResolver struct {
	configurable[*config.EcsConfig]
	NextResolver
	typed
}

// NewEcsResolver creates new resolver instance which adds the subnet information as EDNS0 option
func NewEcsResolver(cfg config.EcsConfig) ChainedResolver {
	return &EcsResolver{
		configurable: withConfig(&cfg),
		typed:        withType("extended_client_subnet"),
	}
}

// Resolve adds the subnet information as EDNS0 option to the request of the next resolver
// and sets the client IP from the EDNS0 option to the request if the client IP is IPv4 or IPv6
// and the corresponding mask is set in the configuration
func (r *EcsResolver) Resolve(request *model.Request) (*model.Response, error) {
	if r.cfg.IsEnabled() {
		if !r.setClientIP(request) {
			r.appendSubnet(request)
		}
	}

	return r.next.Resolve(request)
}

// setClientIP sets the client IP from the EDNS0 option to the request if the
// client IP is IPv4 or IPv6 and the corresponding mask is set in the configuration
func (r *EcsResolver) setClientIP(request *model.Request) bool {
	if so := util.GetEdns0Option(request.Req, dns.EDNS0SUBNET).(*dns.EDNS0_SUBNET); so != nil {
		if (so.Family == ecsIpv4Family && so.SourceNetmask == ecsIpv4Mask) ||
			(so.Family == ecsIpv6Family && so.SourceNetmask == ecsIpv6Mask) {
			request.ClientIP = so.Address
		}
	}

	if !r.cfg.ForwardEcs {
		util.RemoveEdns0Option(request.Req, dns.EDNS0SUBNET)
	}

	return true
}

// appendSubnet appends the subnet information to the request as EDNS0 option
// if the client IP is IPv4 or IPv6 and the corresponding mask is set in the configuration
func (r *EcsResolver) appendSubnet(request *model.Request) {
	e := new(dns.EDNS0_SUBNET)
	e.Code = dns.EDNS0SUBNET
	e.SourceScope = 0

	if ip := request.ClientIP.To4(); ip != nil && r.cfg.IPv4Mask > 0 {
		e.Family = 1
		e.SourceNetmask = r.cfg.IPv4Mask
		e.Address = ip
		util.SetEdns0Option(request.Req, e)
	} else if request.ClientIP.To16() != nil && r.cfg.IPv6Mask > 0 {
		e.Family = 2
		e.SourceNetmask = r.cfg.IPv6Mask
		e.Address = ip
		util.SetEdns0Option(request.Req, e)
	}
}
