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
		It("is true", func() {
			Expect(cfg.IsEnabled()).Should(BeTrue())
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
