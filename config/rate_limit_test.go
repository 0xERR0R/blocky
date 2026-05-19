package config

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RateLimit config", func() {
	Describe("parseCIDRorIP", func() {
		It("parses CIDR notation", func() {
			n, err := parseCIDRorIP("10.0.0.0/8")
			Expect(err).Should(Succeed())
			Expect(n.String()).Should(Equal("10.0.0.0/8"))
		})

		It("parses bare IPv4 as /32", func() {
			n, err := parseCIDRorIP("192.168.1.10")
			Expect(err).Should(Succeed())
			Expect(n.String()).Should(Equal("192.168.1.10/32"))
		})

		It("parses bare IPv6 as /128", func() {
			n, err := parseCIDRorIP("::1")
			Expect(err).Should(Succeed())
			Expect(n.IP.Equal(net.ParseIP("::1"))).Should(BeTrue())
			ones, bits := n.Mask.Size()
			Expect(ones).Should(Equal(128))
			Expect(bits).Should(Equal(128))
		})

		It("parses IPv6 CIDR", func() {
			n, err := parseCIDRorIP("2001:db8::/32")
			Expect(err).Should(Succeed())
			Expect(n.String()).Should(Equal("2001:db8::/32"))
		})

		It("rejects garbage", func() {
			_, err := parseCIDRorIP("not-an-ip")
			Expect(err).Should(HaveOccurred())
		})

		It("rejects empty string", func() {
			_, err := parseCIDRorIP("")
			Expect(err).Should(HaveOccurred())
		})
	})

	Describe("IsEnabled", func() {
		It("is false when Enable is false", func() {
			c := &RateLimit{Enable: false}
			Expect(c.IsEnabled()).Should(BeFalse())
		})
		It("is true when Enable is true", func() {
			c := &RateLimit{Enable: true}
			Expect(c.IsEnabled()).Should(BeTrue())
		})
	})

	Describe("LogConfig", func() {
		suiteBeforeEach()
		It("emits one line per relevant field", func() {
			c := &RateLimit{
				Enable: true, Rate: 50, Burst: 100,
				IPv4Prefix: 32, IPv6Prefix: 64,
				Allowlist: []string{"10.0.0.0/8"},
			}
			c.LogConfig(logger)
			Expect(hook.Calls).ShouldNot(BeEmpty())
		})
	})

	Describe("validate", func() {
		It("accepts disabled config", func() {
			c := &RateLimit{Enable: false}
			Expect(c.validate()).Should(Succeed())
		})
		It("rejects enabled with Rate=0", func() {
			c := &RateLimit{Enable: true, Rate: 0, Burst: 0, IPv4Prefix: 32, IPv6Prefix: 64}
			Expect(c.validate()).Should(MatchError(ContainSubstring("rate must be > 0")))
		})
		It("rejects enabled with non-zero Burst < Rate", func() {
			c := &RateLimit{Enable: true, Rate: 50, Burst: 10, IPv4Prefix: 32, IPv6Prefix: 64}
			Expect(c.validate()).Should(MatchError(ContainSubstring("burst")))
		})
		It("defaults Burst to 2× Rate when left at zero", func() {
			c := &RateLimit{Enable: true, Rate: 50, Burst: 0, IPv4Prefix: 32, IPv6Prefix: 64}
			Expect(c.validate()).Should(Succeed())
			Expect(c.Burst).Should(BeNumerically("==", 100))
		})
		It("rejects IPv4Prefix > 32", func() {
			c := &RateLimit{Enable: true, Rate: 1, Burst: 1, IPv4Prefix: 33, IPv6Prefix: 64}
			Expect(c.validate()).Should(MatchError(ContainSubstring("ipv4Prefix")))
		})
		It("rejects IPv6Prefix > 128", func() {
			c := &RateLimit{Enable: true, Rate: 1, Burst: 1, IPv4Prefix: 32, IPv6Prefix: 129}
			Expect(c.validate()).Should(MatchError(ContainSubstring("ipv6Prefix")))
		})
		It("rejects unparseable allowlist entry", func() {
			c := &RateLimit{
				Enable: true, Rate: 1, Burst: 1,
				IPv4Prefix: 32, IPv6Prefix: 64,
				Allowlist: []string{"garbage"},
			}
			Expect(c.validate()).Should(MatchError(ContainSubstring("garbage")))
		})
		It("accepts bare IPv4 and IPv6 in allowlist", func() {
			c := &RateLimit{
				Enable: true, Rate: 1, Burst: 1,
				IPv4Prefix: 32, IPv6Prefix: 64,
				Allowlist: []string{"127.0.0.1", "::1", "10.0.0.0/8"},
			}
			Expect(c.validate()).Should(Succeed())
			Expect(c.parsedAllowlist).Should(HaveLen(3))
		})
		It("re-parses on repeated calls", func() {
			c := &RateLimit{
				Enable: true, Rate: 1, Burst: 1,
				IPv4Prefix: 32, IPv6Prefix: 64,
				Allowlist: []string{"10.0.0.0/8"},
			}
			Expect(c.validate()).Should(Succeed())
			Expect(c.validate()).Should(Succeed())
			Expect(c.parsedAllowlist).Should(HaveLen(1))
		})
	})
})
