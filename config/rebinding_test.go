package config

import (
	"github.com/0xERR0R/blocky/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RebindingProtection", func() {
	var cfg RebindingProtection

	BeforeEach(func() {
		cfg = RebindingProtection{
			Enable:         true,
			AllowedDomains: []string{"intranet.example.com"},
		}
	})

	Describe("IsEnabled", func() {
		It("is false for the zero value (opt-in)", func() {
			var zero RebindingProtection

			Expect(zero.IsEnabled()).Should(BeFalse())
		})

		It("is true when enabled", func() {
			Expect(cfg.IsEnabled()).Should(BeTrue())
		})
	})

	Describe("LogConfig", func() {
		It("should log something", func() {
			logger, hook := log.NewMockEntry()

			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
		})
	})

	Describe("validate", func() {
		It("accepts a valid allowlist", func() {
			Expect(cfg.validate()).Should(Succeed())
		})

		It("accepts an empty allowlist", func() {
			cfg.AllowedDomains = nil

			Expect(cfg.validate()).Should(Succeed())
		})

		It("rejects empty entries", func() {
			cfg.AllowedDomains = []string{"intranet.example.com", "  "}

			Expect(cfg.validate()).Should(MatchError(ContainSubstring("allowedDomains[1] must not be empty")))
		})

		It("rejects wildcard entries", func() {
			cfg.AllowedDomains = []string{"*.example.com"}

			Expect(cfg.validate()).Should(MatchError(ContainSubstring("plain domain")))
		})

		It("rejects regex entries", func() {
			cfg.AllowedDomains = []string{"/example/"}

			Expect(cfg.validate()).Should(MatchError(ContainSubstring("plain domain")))
		})
	})
})
