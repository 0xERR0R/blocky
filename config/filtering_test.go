package config

import (
	. "github.com/0xERR0R/blocky/helpertest"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("FilteringConfig", func() {
	var cfg Filtering

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = Filtering{
			QueryTypes: NewQTypeSet(AAAA, MX),
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := Filtering{}
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
				cfg := Filtering{}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).Should(HaveLen(3))
			Expect(hook.Messages).Should(ContainElements(
				ContainSubstring("query types:"),
				ContainSubstring("  - AAAA"),
				ContainSubstring("  - MX"),
			))
		})
	})
})
