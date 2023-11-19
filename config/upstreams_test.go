package config

import (
	"time"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParallelBestConfig", func() {
	suiteBeforeEach()

	Context("UpstreamsConfig", func() {
		var cfg UpstreamsConfig

		BeforeEach(func() {
			cfg = UpstreamsConfig{
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
				cfg := UpstreamsConfig{}
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
					cfg := UpstreamsConfig{}

					Expect(cfg.IsEnabled()).Should(BeFalse())
				})
			})
		})

		Describe("LogConfig", func() {
			It("should log configuration", func() {
				cfg.LogConfig(logger)

				Expect(hook.Calls).ShouldNot(BeEmpty())
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("timeout:")))
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("groups:")))
				Expect(hook.Messages).Should(ContainElement(ContainSubstring(":host2:")))
			})
		})
	})

	Context("UpstreamGroupConfig", func() {
		var cfg UpstreamGroup

		BeforeEach(func() {
			cfg = UpstreamGroup{
				Name: UpstreamDefaultCfgName,
				Upstreams: []Upstream{
					{Host: "host1"},
					{Host: "host2"},
				},
			}
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
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("group: default")))
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("upstreams:")))
				Expect(hook.Messages).Should(ContainElement(ContainSubstring(":host1:")))
				Expect(hook.Messages).Should(ContainElement(ContainSubstring(":host2:")))
			})
		})
	})
})
