package resolver

import "net"

func bucketKey(ip net.IP, v4Prefix, v6Prefix uint8) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(int(v4Prefix), 32)).String()
	}
	return ip.To16().Mask(net.CIDRMask(int(v6Prefix), 128)).String()
}
