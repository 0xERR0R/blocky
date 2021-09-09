package util

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"

	"context"
	"fmt"
	"net"
	"time"
)

// Dialer creates a new dialer instance with bootstrap DNS as resolver
func Dialer(cfg *config.Config) *net.Dialer {
	var resolver *net.Resolver

	if cfg.BootstrapDNS != (config.Upstream{}) {
		if cfg.BootstrapDNS.Net == config.NetProtocolTcpUdp {
			dns := net.JoinHostPort(cfg.BootstrapDNS.Host, fmt.Sprint(cfg.BootstrapDNS.Port))
			log.Log().Debugf("using %s as bootstrap dns server", dns)

			resolver = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Millisecond * time.Duration(2000),
					}
					return d.DialContext(ctx, "udp", dns)
				}}
		} else {
			log.Log().Fatal("bootstrap dns net should be tcp+udp")
		}
	}

	return &net.Dialer{
		Timeout:  5 * time.Second,
		Resolver: resolver,
	}
}
