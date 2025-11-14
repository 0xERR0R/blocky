package config

import (
	"net/netip"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("DNS64Config", func() {
	suiteBeforeEach()

	var (
		cfg       *DNS64
		filtering *Filtering
		caching   *Caching
	)

	BeforeEach(func() {
		cfg = &DNS64{}
		filtering = &Filtering{}
		caching = &Caching{}
	})

	Describe("IsEnabled", func() {
		It("should return false by default", func() {
			Expect(cfg.IsEnabled()).Should(BeFalse())
		})

		It("should return true when enabled", func() {
			cfg.Enable = true
			Expect(cfg.IsEnabled()).Should(BeTrue())
		})
	})

	Describe("validate", func() {
		When("DNS64 is disabled", func() {
			It("should not return error", func() {
				cfg.Enable = false
				Expect(cfg.validate(logger, filtering, caching)).Should(Succeed())
			})
		})

		When("DNS64 is enabled", func() {
			BeforeEach(func() {
				cfg.Enable = true
			})

			When("filtering AAAA queries", func() {
				It("should return error", func() {
					filtering.QueryTypes.Insert(dns.Type(dns.TypeAAAA))
					err := cfg.validate(logger, filtering, caching)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("will have no effect"))
					Expect(err.Error()).Should(ContainSubstring("filtering.queryTypes contains AAAA"))
				})
			})

			When("prefixes are valid", func() {
				It("should not return error for well-known prefix", func() {
					cfg.Prefixes = []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}
					Expect(cfg.validate(logger, filtering, caching)).Should(Succeed())
				})

				It("should not return error for all valid prefix lengths", func() {
					cfg.Prefixes = []netip.Prefix{
						netip.MustParsePrefix("2001:db8::/32"),
						netip.MustParsePrefix("2001:db9::/40"),
						netip.MustParsePrefix("2001:dba::/48"),
						netip.MustParsePrefix("2001:dbb::/56"),
						netip.MustParsePrefix("2001:dbc::/64"),
						netip.MustParsePrefix("2001:dbd::/96"),
					}
					Expect(cfg.validate(logger, filtering, caching)).Should(Succeed())
				})

				It("should not return error for empty prefix list", func() {
					cfg.Prefixes = []netip.Prefix{}
					Expect(cfg.validate(logger, filtering, caching)).Should(Succeed())
				})
			})

			When("prefix has invalid length", func() {
				It("should return error for /100", func() {
					cfg.Prefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8::/100")}
					err := cfg.validate(logger, filtering, caching)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("invalid length /100"))
				})

				It("should return error for /24", func() {
					cfg.Prefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8::/24")}
					err := cfg.validate(logger, filtering, caching)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("invalid length /24"))
				})
			})

			When("prefix is IPv4", func() {
				It("should return error", func() {
					cfg.Prefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
					err := cfg.validate(logger, filtering, caching)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("not an IPv6 prefix"))
				})
			})

			When("prefixes overlap", func() {
				It("should return error", func() {
					cfg.Prefixes = []netip.Prefix{
						netip.MustParsePrefix("2001:db8::/32"),
						netip.MustParsePrefix("2001:db8::/48"),
					}
					err := cfg.validate(logger, filtering, caching)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("overlap"))
				})
			})
		})
	})
})
