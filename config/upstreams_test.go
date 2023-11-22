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
