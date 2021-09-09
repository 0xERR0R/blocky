package util

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/net/context"
)

var _ = Describe("Bootstrap resolver configuration", func() {
	Describe("Default config", func() {
		When("BootstrapDns is not configured", func() {
			dialer := Dialer(&config.Config{})
			It("should return a dealer without custom resolver", func() {
				Expect(dialer.Resolver).Should(BeNil())
			})
		})
		When("BootstrapDns is configured UDP resolver", func() {
			dialer := Dialer(&config.Config{
				BootstrapDNS: config.Upstream{
					Net:  config.NetProtocolTcpUdp,
					Host: "0.0.0.0",
					Port: 53,
				},
			})
			It("should return a dealer with custom resolver", func() {
				Expect(dialer.Resolver).Should(Not(BeNil()))
				_, err := dialer.Resolver.Dial(context.Background(), "udp", "test")
				Expect(err).Should(Succeed())
			})
		})

		When("BootstrapDns has wrong (https) configuration", func() {
			It("should log fatal error", func() {
				helpertest.ShouldLogFatal(func() {
					Dialer(&config.Config{
						BootstrapDNS: config.Upstream{
							Net:  config.NetProtocolHttps,
							Host: "1.1.1.1",
							Port: 53,
						},
					})
				})
			})
		})

	})

})
