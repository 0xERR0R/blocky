package resolver

import (
	"github.com/0xERR0R/blocky/util"

	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("IPv6DisablingResolver", func() {
	var (
		sut         *IPv6DisablingResolver
		m           *resolverMock
		mockAnswer  *dns.Msg
		disableIPv6 *bool
		query       = newRequest("example.com", dns.TypeAAAA)
	)

	JustBeforeEach(func() {
		mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 1230, dns.TypeAAAA, "2001:0db8:85a3:08d3:1319:8a2e:0370:7344")
		sut = NewIPv6Checker(*disableIPv6).(*IPv6DisablingResolver)
		m = &resolverMock{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer, Reason: "reason"}, nil)
		sut.Next(m)
	})

	When("Configure IPv6 enabled", func() {
		BeforeEach(func() {
			b := false
			disableIPv6 = &b
		})
		It("Should return one AAAA answer", func() {
			resp, err := sut.Resolve(query)
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.Res.Answer).Should(HaveLen(1))
		})
		It("Configure should output 'accept'", func() {
			c := sut.Configuration()
			Expect(c).Should(HaveLen(1))
			Expect(c[0]).Should(ContainSubstring("accept"))
		})
	})

	When("Configure IPv6 disabled", func() {
		BeforeEach(func() {
			b := true
			disableIPv6 = &b
		})
		It("Should return empty answer without error", func() {
			resp, err := sut.Resolve(query)
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.Res.Answer).Should(HaveLen(0))
		})
		It("Configure should output 'drop'", func() {
			c := sut.Configuration()
			Expect(c).Should(HaveLen(1))
			Expect(c[0]).Should(ContainSubstring("drop"))
		})
	})
})
