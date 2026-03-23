package config

import (
	"time"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParallelBestConfig", func() {
	suiteBeforeEach()

	Context("Upstreams", func() {
		var cfg Upstreams

		BeforeEach(func() {
			cfg = Upstreams{
				Timeout: Duration(5 * time.Second),
				Groups: UpstreamGroups{
					UpstreamDefaultCfgName: {
						{Host: "host1"},
						{Host: "host2"},
					},
				},
			}
		})

		Describe("IsEnabled", func() {
			It("should be false by default", func() {
				cfg := Upstreams{}
				Expect(defaults.Set(&cfg)).Should(Succeed())

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})

			When("enabled", func() {
				It("should be true", func() {
					Expect(cfg.IsEnabled()).Should(BeTrue())
				})
			})

			When("disabled", func() {
				It("should be false", func() {
					cfg := Upstreams{}

					Expect(cfg.IsEnabled()).Should(BeFalse())
				})
			})
		})

		Describe("LogConfig", func() {
			It("should log configuration", func() {
				cfg.LogConfig(logger)

				Expect(hook.Calls).ShouldNot(BeEmpty())
				Expect(hook.Messages).Should(ContainElements(
					ContainSubstring("timeout:"),
					ContainSubstring("groups:"),
					ContainSubstring(":host2:"),
				))
			})

			When("QUIC upstream is configured", func() {
				It("should log QUIC configuration", func() {
					cfg.Groups = UpstreamGroups{
						UpstreamDefaultCfgName: {
							{Host: "dns.example.com", Net: NetProtocolQuic},
						},
					}
					cfg.QUIC = QUICConfig{
						MaxIdleTimeout:  Duration(30 * time.Second),
						KeepAlivePeriod: Duration(15 * time.Second),
					}

					cfg.LogConfig(logger)

					Expect(hook.Messages).Should(ContainElements(
						ContainSubstring("quic:"),
						ContainSubstring("maxIdleTimeout:"),
						ContainSubstring("keepAlivePeriod:"),
					))
				})
			})
		})

		Describe("validate", func() {
			It("should compute defaults", func() {
				cfg.Timeout = -1

				cfg.validate(logger)

				Expect(cfg.Timeout).Should(BeNumerically(">", 0))

				Expect(hook.Calls).ShouldNot(BeEmpty())
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("timeout")))
			})

			It("should not override valid user values", func() {
				cfg.validate(logger)

				Expect(hook.Messages).ShouldNot(ContainElement(ContainSubstring("timeout")))
			})

			When("QUIC upstream is configured", func() {
				BeforeEach(func() {
					cfg.Groups = UpstreamGroups{
						UpstreamDefaultCfgName: {
							{Host: "dns.example.com", Net: NetProtocolQuic},
						},
					}
				})

				It("should warn when QUIC maxIdleTimeout is not above zero", func() {
					cfg.QUIC.MaxIdleTimeout = 0
					cfg.QUIC.KeepAlivePeriod = Duration(15 * time.Second)

					cfg.validate(logger)

					Expect(cfg.QUIC.MaxIdleTimeout).Should(BeNumerically(">", 0))
					Expect(hook.Messages).Should(ContainElement(ContainSubstring("maxIdleTimeout")))
				})

				It("should warn when QUIC keepAlivePeriod is not above zero", func() {
					cfg.QUIC.MaxIdleTimeout = Duration(30 * time.Second)
					cfg.QUIC.KeepAlivePeriod = 0

					cfg.validate(logger)

					Expect(cfg.QUIC.KeepAlivePeriod).Should(BeNumerically(">", 0))
					Expect(hook.Messages).Should(ContainElement(ContainSubstring("keepAlivePeriod")))
				})

				It("should warn when keepAlivePeriod >= maxIdleTimeout", func() {
					cfg.QUIC.MaxIdleTimeout = Duration(10 * time.Second)
					cfg.QUIC.KeepAlivePeriod = Duration(10 * time.Second)

					cfg.validate(logger)

					Expect(hook.Messages).Should(ContainElement(ContainSubstring("keep-alive won't prevent idle timeout")))
				})
			})
		})
	})

	Context("UpstreamGroupConfig", func() {
		var cfg UpstreamGroup

		BeforeEach(func() {
			upstreamsCfg, err := WithDefaults[Upstreams]()
			Expect(err).Should(Succeed())

			cfg = NewUpstreamGroup("test", upstreamsCfg, []Upstream{
				{Host: "host1"},
				{Host: "host2"},
			})
		})

		Describe("IsEnabled", func() {
			It("should be false by default", func() {
				cfg := UpstreamGroup{}
				Expect(defaults.Set(&cfg)).Should(Succeed())

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})

			When("enabled", func() {
				It("should be true", func() {
					Expect(cfg.IsEnabled()).Should(BeTrue())
				})
			})

			When("disabled", func() {
				It("should be false", func() {
					cfg := UpstreamGroup{}

					Expect(cfg.IsEnabled()).Should(BeFalse())
				})
			})
		})

		Describe("LogConfig", func() {
			It("should log configuration", func() {
				cfg.LogConfig(logger)

				Expect(hook.Calls).ShouldNot(BeEmpty())
				Expect(hook.Messages).Should(ContainElements(
					ContainSubstring("group: test"),
					ContainSubstring("upstreams:"),
					ContainSubstring(":host1:"),
					ContainSubstring(":host2:"),
				))
			})
		})
	})
})
