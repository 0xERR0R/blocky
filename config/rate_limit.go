package config

import (
	"fmt"
	"net"
)

func parseCIDRorIP(s string) (*net.IPNet, error) {
	if _, ipNet, err := net.ParseCIDR(s); err == nil {
		return ipNet, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		bits := 128
		if v4 := ip.To4(); v4 != nil {
			ip = v4
			bits = 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	return nil, fmt.Errorf("not a valid CIDR or IP: %q", s)
}
