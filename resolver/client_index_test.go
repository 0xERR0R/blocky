package resolver

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("clientIndex", func() {
	var idx clientIndex[string]

	BeforeEach(func() {
		idx = newClientIndex(map[string]string{
			"laptop":         "name",
			"lap*":           "glob lap*",
			"l*":             "glob l*",
			"10.0.0.5":       "ip",
			"10.0.0.0/8":     "cidr /8",
			"10.0.0.0/24":    "cidr /24",
			"10.0.0.1/24":    "cidr /24 again",
			"client.example": "fqdn",
		})
	})

	Describe("forEachMatch", func() {
		It("yields every match: per name the literal, then globs; then the IP; then each CIDR", func() {
			var got []string

			idx.forEachMatch([]string{"Laptop"}, net.ParseIP("10.0.0.5"), func(v string) { got = append(got, v) })

			Expect(got).Should(Equal([]string{
				"name", "glob l*", "glob lap*", "ip", "cidr /24", "cidr /8", "cidr /24 again",
			}))
		})

		It("does not resolve FQDN identifiers", func() {
			var got []string

			idx.forEachMatch(nil, net.ParseIP("192.0.2.1"), func(v string) { got = append(got, v) })

			Expect(got).Should(BeEmpty())
			Expect(idx.fqdns).ShouldNot(BeEmpty())
		})
	})

	Describe("mostSpecific", func() {
		DescribeTable("picks one value",
			func(names []string, ip string, expected string) {
				v, found := idx.mostSpecific(names, net.ParseIP(ip))

				Expect(found).Should(BeTrue())
				Expect(v).Should(Equal(expected))
			},
			Entry("literal name over everything", []string{"LAPTOP"}, "10.0.0.5", "name"),
			Entry("exact IP over a glob", []string{"lapdog"}, "10.0.0.5", "ip"),
			Entry("glob over a CIDR, first pattern in order", []string{"lapdog"}, "10.0.0.9", "glob l*"),
			Entry("longest CIDR prefix, first identifier on a tie", nil, "10.0.0.9", "cidr /24"),
			Entry("a shorter CIDR when only it matches", nil, "10.9.9.9", "cidr /8"),
			Entry("an FQDN identifier as a literal client name", []string{"client.example"}, "192.0.2.1", "fqdn"),
		)

		It("finds nothing for an unknown client", func() {
			_, found := idx.mostSpecific([]string{"phone"}, net.ParseIP("192.0.2.1"))

			Expect(found).Should(BeFalse())
		})

		It("handles a request without client IP", func() {
			_, found := idx.mostSpecific(nil, nil)

			Expect(found).Should(BeFalse())
		})
	})
})
