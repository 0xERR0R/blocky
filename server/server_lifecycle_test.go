// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Stop has to hand the ports back before it returns.
//
// It used to release the HTTP and HTTPS listeners only via the
// context-cancellation goroutine in httpServer.Serve, so whether the port was
// actually free when Stop returned came down to goroutine scheduling. That made
// any rebind of the same port — a restart, or the next spec in a suite — fail
// with "address already in use" on a loaded machine while passing everywhere
// else. It surfaced as a CI-only flake in the admin-port specs above.
var _ = Describe("Server lifecycle", func() {
	var (
		ctx      context.Context
		cancelFn context.CancelFunc

		// Reserved once per spec, not per server: the point of the spec is that
		// the second cycle rebinds the very same ports the first one released.
		dnsAddr   string
		httpAddr  string
		adminAddr string
	)

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		dnsAddr = NextFreeHostPort("127.0.0.1")
		httpAddr = NextFreeHostPort("")
		adminAddr = NextFreeHostPort("")
	})

	newServerOnSamePorts := func() (*Server, error) {
		return NewServer(ctx, &config.Config{
			Upstreams: config.Upstreams{
				Groups: map[string][]config.Upstream{
					"default": {config.Upstream{Net: config.NetProtocolTcpUdp, Host: "8.8.8.8", Port: 53}},
				},
			},
			CustomDNS: config.CustomDNS{
				Mapping: config.CustomDNSMapping{
					"custom.lan": {&dns.A{A: net.ParseIP("192.168.178.55")}},
				},
			},
			Blocking: config.Blocking{BlockType: "zeroIp"},
			Ports: config.Ports{
				DNS:       config.ListenConfig{dnsAddr},
				HTTP:      config.ListenConfig{httpAddr},
				AdminPort: config.ListenConfig{adminAddr},
				DOHPath:   "/dns-query",
			},
		}, nil)
	}

	It("should release its ports on Stop, without relying on the context", func() {
		// Two cycles on the same ports. The context stays alive throughout, so
		// only Stop can be what frees them.
		for range 2 {
			sut, err := newServerOnSamePorts()
			Expect(err).Should(Succeed())

			errChan := make(chan error, 10)
			go sut.Start(ctx, errChan)

			Consistently(errChan, "500ms").ShouldNot(Receive())

			Expect(sut.Stop(ctx)).Should(Succeed())

			// A clean stop is not a failure: Serve returns ErrServerClosed
			// once Shutdown has run, and that must not reach the error channel.
			Consistently(errChan, "100ms").ShouldNot(Receive())
		}
	})
})
