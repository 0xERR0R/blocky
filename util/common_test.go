package util

import (
	"net"

	"github.com/miekg/dns"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Common function tests", func() {
	Describe("Split string in chunks", func() {
		When("String length < chunk size", func() {
			It("should return one chunk", func() {
				chunks := Chunks("mystring", 10)

				Expect(chunks).Should(HaveLen(1))
				Expect(chunks).Should(ContainElement("mystring"))
			})
		})

		When("String length > chunk size", func() {
			It("should return multiple chunks", func() {
				chunks := Chunks("myveryveryverylongstring", 5)

				Expect(chunks).Should(HaveLen(5))
				Expect(chunks).Should(ContainElements("myver", "yvery", "veryl", "ongst", "ring"))
			})
		})
	})

	Describe("Print DNS answer", func() {
		When("different types of DNS answers", func() {
			rr := make([]dns.RR, 0)
			rr = append(rr, &dns.A{A: net.ParseIP("127.0.0.1")})
			rr = append(rr, &dns.AAAA{AAAA: net.ParseIP("2001:0db8:85a3:08d3:1319:8a2e:0370:7344")})
			rr = append(rr, &dns.CNAME{Target: "cname"})
			rr = append(rr, &dns.PTR{Ptr: "ptr"})
			rr = append(rr, &dns.NS{Ns: "ns"})
			It("should print the answers", func() {
				answerToString := AnswerToString(rr)
				Expect(answerToString).Should(Equal("A (127.0.0.1), " +
					"AAAA (2001:db8:85a3:8d3:1319:8a2e:370:7344), CNAME (cname), PTR (ptr), \t0\tCLASS0\tNone\tns"))
			})
		})
	})
})
