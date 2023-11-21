package config

import (
	"net"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ClientLookupConfig", func() {
	var cfg ClientLookup

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = ClientLookup{
			Upstream:        Upstream{Net: NetProtocolTcpUdp, Host: "host"},
			SingleNameOrder: []uint{1, 2},
			ClientnameIPMapping: map[string][]net.IP{
				"client8": {net.ParseIP("1.2.3.5")},
			},
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg = ClientLookup{}
			Expect(defaults.Set(&cfg)).Should(Succeed())

			Expect(cfg.IsEnabled()).Should(BeFalse())
		})

		When("enabled", func() {
			It("should be true", func() {
				By("upstream", func() {
					cfg := ClientLookup{
						Upstream:            Upstream{Net: NetProtocolTcpUdp, Host: "host"},
						ClientnameIPMapping: nil,
					}

					Expect(cfg.IsEnabled()).Should(BeTrue())
				})

				By("mapping", func() {
					cfg := ClientLookup{
						ClientnameIPMapping: map[string][]net.IP{
							"client8": {net.ParseIP("1.2.3.5")},
						},
					}

					Expect(cfg.IsEnabled()).Should(BeTrue())
				})
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("client IP mapping:")))
		})
	})
})
