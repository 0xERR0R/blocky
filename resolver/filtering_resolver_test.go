package resolver

import (
	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("FilteringResolver", func() {
	var (
		sut        *FilteringResolver
		sutConfig  config.FilteringConfig
		m          *mockResolver
		mockAnswer *dns.Msg
	)

	BeforeEach(func() {
		mockAnswer = new(dns.Msg)
	})

	JustBeforeEach(func() {
		sut = NewFilteringResolver(sutConfig).(*FilteringResolver)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)
		sut.Next(m)
	})

	When("Filtering query types are defined", func() {
		BeforeEach(func() {
			sutConfig = config.FilteringConfig{
				QueryTypes: config.NewQTypeSet(dns.Type(dns.TypeAAAA), dns.Type(dns.TypeMX)),
			}
		})
		It("Should delegate to next resolver if request query has other type", func() {
			resp, err := sut.Resolve(newRequest("example.com", dns.Type(dns.TypeA)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
			Expect(resp.Res.Answer).Should(BeEmpty())
			// delegated to next resolver
			Expect(m.Calls).Should(HaveLen(1))
		})
		It("Should return empty answer for defined query type", func() {
			resp, err := sut.Resolve(newRequest("example.com", dns.Type(dns.TypeAAAA)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.RType).Should(Equal(ResponseTypeFILTERED))
			Expect(resp.Res.Answer).Should(BeEmpty())

			// no call of next resolver
			Expect(m.Calls).Should(BeZero())
		})
		It("Configure should output all query types", func() {
			c := sut.Configuration()
			Expect(c).Should(Equal([]string{"filtering query Types: 'AAAA, MX'"}))
		})
	})

	When("No filtering query types are defined", func() {
		BeforeEach(func() {
			sutConfig = config.FilteringConfig{}
		})
		It("Should return empty answer without error", func() {
			resp, err := sut.Resolve(newRequest("example.com", dns.Type(dns.TypeAAAA)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
			Expect(resp.Res.Answer).Should(HaveLen(0))
		})
		It("Configure should output 'empty list'", func() {
			c := sut.Configuration()
			Expect(c).Should(ContainElement(configStatusDisabled))
		})
	})
})
