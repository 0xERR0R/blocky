package resolver

import (
	"context"
	"fmt"
	"net"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
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
		ctx, logger := r.log(ctx)
		_ = ctx

		so := util.GetEdns0Option[*dns.EDNS0_SUBNET](request.Req)
		// Set the client IP from the Edns0 subnet option if the option is enabled and the correct subnet mask is set
		if r.cfg.UseAsClient && so != nil && ((so.Family == ecsFamilyIPv4 && so.SourceNetmask == ecsMaskIPv4) ||
			(so.Family == ecsFamilyIPv6 && so.SourceNetmask == ecsMaskIPv6)) {
			logger.Debugf("using request's edns0 address as internal client IP: %s", so.Address)
			request.ClientIP = so.Address
		}

		// Set the Edns0 subnet option if the client IP is IPv4 or IPv6 and the masks are set in the configuration
		if r.cfg.IPv4Mask > 0 || r.cfg.IPv6Mask > 0 {
			r.setSubnet(so, request, logger)
		}

		// Remove the Edns0 subnet option if the client IP is IPv4 or IPv6 and the corresponding mask is not set
		// and the forwardEcs option is not enabled
		if r.cfg.IPv4Mask == 0 && r.cfg.IPv6Mask == 0 && so != nil && !r.cfg.Forward {
			logger.Debug("remove edns0 subnet option")
			util.RemoveEdns0Option[*dns.EDNS0_SUBNET](request.Req)
		}
	}

	return r.next.Resolve(ctx, request)
}

// setSubnet appends the subnet information to the request as EDNS0 option
// if the client IP is IPv4 or IPv6 and the corresponding mask is set in the configuration
func (r *ECSResolver) setSubnet(so *dns.EDNS0_SUBNET, request *model.Request, logger *logrus.Entry) {
	var subIP net.IP
	if so != nil && r.cfg.Forward && so.Address != nil {
		subIP = so.Address
	} else {
		subIP = request.ClientIP
	}

	var edsOption *dns.EDNS0_SUBNET

	if ip := subIP.To4(); ip != nil && r.cfg.IPv4Mask > 0 {
		if mip, err := maskIP(ip, r.cfg.IPv4Mask); err == nil {
			edsOption = newEdnsSubnetOption(mip, ecsFamilyIPv4, r.cfg.IPv4Mask)
		}
	} else if ip := subIP.To16(); ip != nil && r.cfg.IPv6Mask > 0 {
		if mip, err := maskIP(ip, r.cfg.IPv6Mask); err == nil {
			edsOption = newEdnsSubnetOption(mip, ecsFamilyIPv6, r.cfg.IPv6Mask)
		}
	}

	if edsOption != nil {
		logger.Debugf("set edns0 subnet option address: %s", edsOption.Address)
		util.SetEdns0Option(request.Req, edsOption)
	}
}

// maskIP masks the IP with the given mask and return an error if the mask is invalid
func maskIP[maskType ECSMask](ip net.IP, mask maskType) (net.IP, error) {
	_, mip, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), mask))

	return mip.IP, err
}

// newEdnsSubnetOption( creates a new EDNS0 subnet option with the given IP, family and mask
func newEdnsSubnetOption[maskType ECSMask](ip net.IP, family uint16, mask maskType) *dns.EDNS0_SUBNET {
	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		SourceScope:   ecsSourceScope,
		Family:        family,
		SourceNetmask: uint8(mask),
		Address:       ip,
	}
}
