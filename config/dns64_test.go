package config

import (
	"net/netip"
	"time"

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

	Describe("LogConfig", func() {
		It("should log default prefixes when empty", func() {
			cfg.LogConfig(logger)
			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("64:ff9b::/96")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("default")))
		})

		It("should log custom prefixes when configured", func() {
			cfg.Prefixes = []netip.Prefix{
				netip.MustParsePrefix("2001:db8::/32"),
				netip.MustParsePrefix("2001:db9::/96"),
			}
			cfg.LogConfig(logger)
			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("2001:db8::/32")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("2001:db9::/96")))
		})

		It("should log default exclusionSet when empty", func() {
			cfg.LogConfig(logger)
			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("::ffff:0:0/96")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("default, plus configured prefixes")))
		})

		It("should log custom exclusionSet when configured", func() {
			cfg.ExclusionSet = []netip.Prefix{
				netip.MustParsePrefix("2001:db8::/64"),
			}
			cfg.LogConfig(logger)
			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("exclusionSet (custom)")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("2001:db8::/64")))
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

			When("exclusionSet contains IPv4 prefix", func() {
				It("should return error", func() {
					cfg.ExclusionSet = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
					err := cfg.validate(logger, filtering, caching)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("exclusion set prefix"))
					Expect(err.Error()).Should(ContainSubstring("not an IPv6 prefix"))
				})
			})

			When("exclusionSet contains valid IPv6 prefix", func() {
				It("should not return error", func() {
					cfg.ExclusionSet = []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}
					caching.MaxCachingTime = Duration(5 * time.Minute)
					Expect(cfg.validate(logger, filtering, caching)).Should(Succeed())
				})
			})

			When("caching is disabled", func() {
				It("should log warning", func() {
					caching.MaxCachingTime = Duration(-1)
					_ = cfg.validate(logger, filtering, caching)
					Expect(hook.Calls).ShouldNot(BeEmpty())
					Expect(hook.Messages).Should(ContainElement(ContainSubstring("DNS64 is enabled but caching is disabled")))
					Expect(hook.Messages).Should(ContainElement(ContainSubstring("reduced performance")))
				})
			})

			When("caching is enabled", func() {
				It("should not log warning about caching", func() {
					caching.MaxCachingTime = Duration(5 * time.Minute)
					_ = cfg.validate(logger, filtering, caching)
					// Check no warning about caching was logged
					for _, msg := range hook.Messages {
						if msg == "DNS64 is enabled but caching is disabled" {
							Fail("Should not log caching disabled warning when caching is enabled")
						}
					}
				})
			})
		})
	})
})
