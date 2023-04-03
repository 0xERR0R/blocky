package config

import (
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("MetricsConfig", func() {
	var cfg MetricsConfig

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = MetricsConfig{
			Enable: true,
			Path:   "/custom/path",
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := MetricsConfig{}
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
				cfg := MetricsConfig{}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).Should(HaveLen(1))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("url path: /custom/path")))
		})
	})
})
