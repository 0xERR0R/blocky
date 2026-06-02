//go:build linux

package server

import (
	"context"
	"net"

	"github.com/0xERR0R/blocky/config"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// 192.0.2.1 is in TEST-NET-1 (RFC 5737) and is never assigned to a real
// interface, so binding to it only succeeds with IP_FREEBIND.
const nonLocalDNSAddr = "192.0.2.1:0"

var _ = Describe("createServers with freeBind", func() {
	BeforeEach(func(ctx context.Context) {
		// If the environment already permits non-local binds (e.g. ip_nonlocal_bind),
		// we cannot attribute success to IP_FREEBIND, so skip.
		lc := net.ListenConfig{}
		if l, err := lc.Listen(ctx, "tcp", nonLocalDNSAddr); err == nil {
			_ = l.Close()
			Skip("environment permits non-local bind; cannot validate freeBind")
		}
	})

	When("freeBind is enabled", func() {
		It("pre-binds the DNS listeners to a not-yet-available address", func(ctx context.Context) {
			cfg := &config.Config{
				Ports: config.Ports{
					DNS:      config.ListenConfig{nonLocalDNSAddr},
					FreeBind: true,
				},
			}

			servers, err := createServers(ctx, cfg, nil)
			Expect(err).ToNot(HaveOccurred())
			// one UDP + one TCP server for the single DNS address
			Expect(servers).To(HaveLen(2))

			for _, srv := range servers {
				DeferCleanup(func() {
					if srv.PacketConn != nil {
						_ = srv.PacketConn.Close()
					}

					if srv.Listener != nil {
						_ = srv.Listener.Close()
					}
				})

				Expect(srv.PacketConn != nil || srv.Listener != nil).
					To(BeTrue(), "expected a pre-created socket for %s", srv.Net)
			}
		})
	})

	When("freeBind is disabled", func() {
		It("does not pre-create listeners (miekg/dns binds at start)", func(ctx context.Context) {
			cfg := &config.Config{
				Ports: config.Ports{
					DNS:      config.ListenConfig{nonLocalDNSAddr},
					FreeBind: false,
				},
			}

			servers, err := createServers(ctx, cfg, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(servers).To(HaveLen(2))

			for _, srv := range servers {
				Expect(srv.PacketConn).To(BeNil())
				Expect(srv.Listener).To(BeNil())
			}
		})
	})
})
