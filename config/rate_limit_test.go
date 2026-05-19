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
})
