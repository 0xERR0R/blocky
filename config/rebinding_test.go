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
			lgr, rec := log.NewRecorder()

			cfg.LogConfig(lgr)

			Expect(rec.Records()).ShouldNot(BeEmpty())
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

		It("rejects padded entries", func() {
			cfg.AllowedDomains = []string{" intranet.example.com"}

			Expect(cfg.validate()).Should(MatchError(ContainSubstring("plain domain")))
		})

		It("rejects entries with non-ASCII whitespace", func() {
			// the rejected set must match the normalization's definition of
			// whitespace (unicode.IsSpace), not just the ASCII subset
			cfg.AllowedDomains = []string{"\u00a0intranet.example.com"}

			Expect(cfg.validate()).Should(MatchError(ContainSubstring("plain domain")))
		})

		It("rejects dot-degenerate entries", func() {
			cfg.AllowedDomains = []string{"."}

			Expect(cfg.validate()).Should(MatchError(ContainSubstring("plain domain")))
		})

		It("accepts underscore, punycode and digit/hyphen entries", func() {
			cfg.AllowedDomains = []string{"_dmarc.example.com", "xn--br-via.example.com", "host-1.example.com"}

			Expect(cfg.validate()).Should(Succeed())
		})
	})

	Describe("NormalizedAllowedDomains", func() {
		It("returns entries lowercased and without trailing dot after validate", func() {
			cfg.AllowedDomains = []string{"Intranet.Example.COM."}

			Expect(cfg.validate()).Should(Succeed())
			Expect(cfg.NormalizedAllowedDomains()).Should(ConsistOf("intranet.example.com"))
		})

		It("normalizes on the fly when validate has not run", func() {
			// configs hand-built in tests skip validate; canonicalization must
			// not depend on it
			cfg.AllowedDomains = []string{"Router.LAN."}

			Expect(cfg.NormalizedAllowedDomains()).Should(ConsistOf("router.lan"))
		})
	})
})
