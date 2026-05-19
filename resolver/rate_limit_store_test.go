package resolver

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("bucketKey", func() {
	It("uses /32 mask for IPv4", func() {
		Expect(bucketKey(net.ParseIP("192.0.2.5"), 32, 64)).Should(Equal("192.0.2.5"))
	})

	It("aggregates IPv4 by configured prefix", func() {
		a := bucketKey(net.ParseIP("192.0.2.5"), 24, 64)
		b := bucketKey(net.ParseIP("192.0.2.99"), 24, 64)
		Expect(a).Should(Equal(b))
	})

	It("aggregates IPv6 by /64 default", func() {
		a := bucketKey(net.ParseIP("2001:db8::1"), 32, 64)
		b := bucketKey(net.ParseIP("2001:db8::ffff"), 32, 64)
		Expect(a).Should(Equal(b))
	})

	It("separates different IPv6 /64s", func() {
		a := bucketKey(net.ParseIP("2001:db8:1::1"), 32, 64)
		b := bucketKey(net.ParseIP("2001:db8:2::1"), 32, 64)
		Expect(a).ShouldNot(Equal(b))
	})

	It("normalises IPv4-mapped IPv6 to v4", func() {
		mapped := net.ParseIP("::ffff:192.0.2.5")
		v4 := net.ParseIP("192.0.2.5")
		Expect(bucketKey(mapped, 32, 64)).Should(Equal(bucketKey(v4, 32, 64)))
	})
})
