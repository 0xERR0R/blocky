package util

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParseIPFromArpaAddr", func() {
	Describe("IPv4", func() {
		It("parses an IP correctly", func() {
			ip, err := ParseIPFromArpaAddr("4.3.2.1.in-addr.arpa.")
			Expect(err).Should(Succeed())
			Expect(ip).Should(Equal(net.ParseIP("1.2.3.4")))
		})

		It("requires the arpa domain", func() {
			_, err := ParseIPFromArpaAddr("4.3.2.1.in-addr.arpa.fail.")
			Expect(err).ShouldNot(Succeed())

			_, err = ParseIPFromArpaAddr("4.3.2.1.in-addr.fail.arpa.")
			Expect(err).ShouldNot(Succeed())

			_, err = ParseIPFromArpaAddr("4.3.2.1.fail.in-addr.arpa.")
			Expect(err).ShouldNot(Succeed())
		})

		It("requires all ip parts to be decimal numbers", func() {
			_, err := ParseIPFromArpaAddr("a.3.2.1.in-addr.arpa.")
			Expect(err).ShouldNot(Succeed())
		})

		It("requires all parts to be present", func() {
			_, err := ParseIPFromArpaAddr("3.2.1.in-addr.arpa.")
			Expect(err).ShouldNot(Succeed())
		})

		It("requires all parts to be non empty", func() {
			_, err := ParseIPFromArpaAddr(".3.2.1.in-addr.arpa.")
			Expect(err).ShouldNot(Succeed())

			_, err = ParseIPFromArpaAddr("4..2.1.in-addr.arpa.")
			Expect(err).ShouldNot(Succeed())

			_, err = ParseIPFromArpaAddr("4.3..1.in-addr.arpa.")
			Expect(err).ShouldNot(Succeed())

			_, err = ParseIPFromArpaAddr("4.3.2..in-addr.arpa.")
			Expect(err).ShouldNot(Succeed())
		})
	})

	Describe("IPv6", func() {
		It("parses an IP correctly", func() {
			ip, err := ParseIPFromArpaAddr("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.f.7.2.0.0.2.ip6.arpa.")
			Expect(err).Should(Succeed())
			Expect(ip).Should(Equal(net.ParseIP("2002:7f00:1::1")))
		})

		It("requires the arpa domain", func() {
			_, err := ParseIPFromArpaAddr("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.f.7.2.0.0.2.ip6.arpa.fail.")
			Expect(err).ShouldNot(Succeed())

			_, err = ParseIPFromArpaAddr("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.f.7.2.0.0.2.ip6.fail.arpa.")
			Expect(err).ShouldNot(Succeed())

			_, err = ParseIPFromArpaAddr("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.f.7.2.0.0.2.fail.ip6.arpa.")
			Expect(err).ShouldNot(Succeed())
		})

		It("requires all LSB parts to be hex numbers", func() {
			_, err := ParseIPFromArpaAddr("g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.f.7.2.0.0.2.ip6.arpa.")
			Expect(err).ShouldNot(Succeed())
		})

		It("requires all MSB parts to be hex numbers", func() {
			_, err := ParseIPFromArpaAddr("1.g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.f.7.2.0.0.2.ip6.arpa.")
			Expect(err).ShouldNot(Succeed())
		})

		It("requires all parts to be present", func() {
			_, err := ParseIPFromArpaAddr("1.0.0.0.0.0.0.0.0.0.0.0.0.g.0.0.0.0.1.0.0.0.0.0.f.7.2.0.0.2.ip6.arpa.")
			Expect(err).ShouldNot(Succeed())
		})

		It("requires all parts to non empty", func() {
			_, err := ParseIPFromArpaAddr(".0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.f.7.2.0.0.2.ip6.arpa.")
			Expect(err).ShouldNot(Succeed())

			_, err = ParseIPFromArpaAddr("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0..0.0.0.0.1.0.0.0.0.0.f.7.2.0.0.2.ip6.arpa.")
			Expect(err).ShouldNot(Succeed())

			_, err = ParseIPFromArpaAddr("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0..0.0.0.0.1.0.0.0.0.0.f.7.2.0.0..ip6.arpa.")
			Expect(err).ShouldNot(Succeed())
		})
	})
})
