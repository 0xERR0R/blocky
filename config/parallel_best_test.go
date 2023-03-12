package config

import (
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParallelBestConfig", func() {
	var (
		cfg ParallelBestConfig
	)

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = ParallelBestConfig{
			ExternalResolvers: ParallelBestMapping{
				UpstreamDefaultCfgName: {
					{Host: "host1"},
					{Host: "host2"},
				},
			},
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := ParallelBestConfig{}
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
				cfg := ParallelBestConfig{}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("upstream resolvers:")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring(":host2:")))
		})
	})
})
