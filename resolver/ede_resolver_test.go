package resolver

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("EdeResolver", func() {
	var (
		sut        *EdeResolver
		sutConfig  config.EdeConfig
		m          *MockResolver
		mockAnswer *dns.Msg
	)

	BeforeEach(func() {
		mockAnswer = new(dns.Msg)
	})

	JustBeforeEach(func() {
		m = &MockResolver{}
		m.On("Resolve", mock.Anything).Return(&model.Response{
			Res:    mockAnswer,
			RType:  model.ResponseTypeCUSTOMDNS,
			Reason: "Test",
		}, nil)

		sut = NewEdeResolver(sutConfig).(*EdeResolver)
		sut.Next(m)
	})

	When("Ede is disabled", func() {
		BeforeEach(func() {
			sutConfig = config.EdeConfig{
				Enable: false,
			}
		})
		It("Shouldn't add EDE information", func() {
			resp, err := sut.Resolve(newRequest("example.com", dns.Type(dns.TypeA)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.RType).Should(Equal(model.ResponseTypeCUSTOMDNS))
			Expect(resp.Res.Answer).Should(BeEmpty())
			Expect(resp.Res.Extra).Should(BeEmpty())

			// delegated to next resolver
			Expect(m.Calls).Should(HaveLen(1))
		})
		It("Configure should output deactivated", func() {
			c := sut.Configuration()
			Expect(c).Should(HaveLen(1))
			Expect(c[0]).Should(Equal("deactivated"))
		})
	})
	When("Ede is enabled", func() {
		BeforeEach(func() {
			sutConfig = config.EdeConfig{
				Enable: true,
			}
		})
		It("Should add EDE information", func() {
			resp, err := sut.Resolve(newRequest("example.com", dns.Type(dns.TypeA)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.RType).Should(Equal(model.ResponseTypeCUSTOMDNS))
			Expect(resp.Res.Answer).Should(BeEmpty())
			Expect(resp.Res.Extra).Should(HaveLen(1))
			opt, ok := resp.Res.Extra[0].(*dns.OPT)
			Expect(ok).Should(BeTrue())
			Expect(opt).ShouldNot(BeNil())
			ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
			Expect(ok).Should(BeTrue())
			Expect(ede.InfoCode).Should(Equal(dns.ExtendedErrorCodeForgedAnswer))
			Expect(ede.ExtraText).Should(Equal("Test"))
		})
		It("Configure should output activated", func() {
			c := sut.Configuration()
			Expect(c).Should(HaveLen(1))
			Expect(c[0]).Should(Equal("activated"))
		})
	})
})
