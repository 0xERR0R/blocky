package config

import (
	. "github.com/0xERR0R/blocky/helpertest"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("FilteringConfig", func() {
	var cfg FilteringConfig

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = FilteringConfig{
			QueryTypes: NewQTypeSet(AAAA, MX),
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := FilteringConfig{}
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
				cfg := FilteringConfig{}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).Should(HaveLen(3))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("query types:")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("  - AAAA")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("  - MX")))
		})
	})
})
