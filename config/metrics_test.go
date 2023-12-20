package config

import (
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("MetricsConfig", func() {
	var cfg Metrics

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = Metrics{
			Enable: true,
			Path:   "/custom/path",
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := Metrics{}
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
				cfg := Metrics{}

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
