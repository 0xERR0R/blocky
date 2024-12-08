package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SUDNConfig", func() {
	var cfg SUDN

	suiteBeforeEach()

	BeforeEach(func() {
		var err error

		cfg, err = WithDefaults[SUDN]()
		Expect(err).Should(Succeed())
	})

	Describe("IsEnabled", func() {
		It("should be true by default", func() {
			Expect(cfg.IsEnabled()).Should(BeTrue())
		})

		When("enabled", func() {
			It("should be true", func() {
				cfg := SUDN{
					Enable: true,
				}
				Expect(cfg.IsEnabled()).Should(BeTrue())
			})
		})

		When("disabled", func() {
			It("should be false", func() {
				cfg := SUDN{
					Enable: false,
				}
				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("rfc6762-appendixG = true")))
		})
	})
})
