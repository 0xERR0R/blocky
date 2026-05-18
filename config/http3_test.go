package config

import (
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HTTP3Config", func() {
	suiteBeforeEach()

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := HTTP3{}
			Expect(defaults.Set(&cfg)).Should(Succeed())
			Expect(cfg.IsEnabled()).Should(BeFalse())
		})

		When("enabled", func() {
			It("should be true", func() {
				cfg := HTTP3{Enable: true}
				Expect(cfg.IsEnabled()).Should(BeTrue())
			})
		})

		When("disabled", func() {
			It("should be false", func() {
				cfg := HTTP3{Enable: false}
				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log enabled exactly once", func() {
			cfg := HTTP3{Enable: true}
			cfg.LogConfig(logger)

			Expect(hook.Calls).Should(HaveLen(1))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("enabled")))
		})
	})
})
