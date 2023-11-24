package config

import (
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RewriterConfig", func() {
	var cfg RewriterConfig

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = RewriterConfig{
			Rewrite: map[string]string{
				"original1": "rewritten1",
				"original2": "rewritten2",
			},
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := RewriterConfig{}
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
				cfg := RewriterConfig{}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElements(
				ContainSubstring("rules:"),
				ContainSubstring("original2 ="),
			))
		})
	})
})
