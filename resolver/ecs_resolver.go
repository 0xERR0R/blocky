package resolver

import (
	"context"
	"fmt"
	"net"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

// https://www.rfc-editor.org/rfc/rfc7871.html#section-6
const (
	ecsSourceScope = uint8(0)

	ecsMaskIPv4 = uint8(net.IPv4len * 8)
	ecsMaskIPv6 = uint8(net.IPv6len * 8)
)

// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
const (
	ecsFamilyIPv4 = uint16(iota + 1)
	ecsFamilyIPv6
)

// ECSMask is an interface for all ECS subnet masks as type constraint for generics
type ECSMask interface {
	config.ECSv4Mask | config.ECSv6Mask
}

// ECSResolver is responsible for adding the EDNS Client Subnet information as EDNS0 option.
type ECSResolver struct {
	configurable[*config.ECS]
	NextResolver
	typed
}

// NewECSResolver creates new resolver instance which adds the subnet information as EDNS0 option
func NewECSResolver(cfg config.ECS) ChainedResolver {
	return &ECSResolver{
		configurable: withConfig(&cfg),
		typed:        withType("extended_client_subnet"),
	}
}

// Resolve adds the subnet information as EDNS0 option to the request of the next resolver
// and sets the client IP from the EDNS0 option to the request if this option is enabled
func (r *ECSResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	if r.cfg.IsEnabled() {
		so := util.GetEdns0Option[*dns.EDNS0_SUBNET](request.Req)
		// Set the client IP from the Edns0 subnet option if the option is enabled and the correct subnet mask is set
		if r.cfg.UseAsClient && so != nil && ((so.Family == ecsFamilyIPv4 && so.SourceNetmask == ecsMaskIPv4) ||
			(so.Family == ecsFamilyIPv6 && so.SourceNetmask == ecsMaskIPv6)) {
			request.ClientIP = so.Address
		}

		// Set the Edns0 subnet option if the client IP is IPv4 or IPv6 and the masks are set in the configuration
		if r.cfg.IPv4Mask > 0 || r.cfg.IPv6Mask > 0 {
			r.setSubnet(request)
		}

		// Remove the Edns0 subnet option if the client IP is IPv4 or IPv6 and the corresponding mask is not set
		// and the forwardEcs option is not enabled
		if r.cfg.IPv4Mask == 0 && r.cfg.IPv6Mask == 0 && so != nil && !r.cfg.Forward {
			util.RemoveEdns0Option[*dns.EDNS0_SUBNET](request.Req)
		}
	}

	return r.next.Resolve(ctx, request)
}

// setSubnet appends the subnet information to the request as EDNS0 option
// if the client IP is IPv4 or IPv6 and the corresponding mask is set in the configuration
func (r *ECSResolver) setSubnet(request *model.Request) {
	e := new(dns.EDNS0_SUBNET)
	e.Code = dns.EDNS0SUBNET
	e.SourceScope = ecsSourceScope

	if ip := request.ClientIP.To4(); ip != nil && r.cfg.IPv4Mask > 0 {
		mip, err := maskIP(ip, r.cfg.IPv4Mask)
		if err == nil {
			e.Family = ecsFamilyIPv4
			e.SourceNetmask = uint8(r.cfg.IPv4Mask)
			e.Address = mip
			util.SetEdns0Option(request.Req, e)
		}
	} else if ip := request.ClientIP.To16(); ip != nil && r.cfg.IPv6Mask > 0 {
		mip, err := maskIP(ip, r.cfg.IPv6Mask)
		if err == nil {
			e.Family = ecsFamilyIPv6
			e.SourceNetmask = uint8(r.cfg.IPv6Mask)
			e.Address = mip
			util.SetEdns0Option(request.Req, e)
		}
	}
}

// maskIP masks the IP with the given mask and return an error if the mask is invalid
func maskIP[maskType ECSMask](ip net.IP, mask maskType) (net.IP, error) {
	_, mip, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), mask))

	return mip.IP, err
}
