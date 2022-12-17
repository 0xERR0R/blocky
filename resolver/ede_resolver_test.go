package resolver

import (
	"errors"

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
		m          *mockResolver
		mockAnswer *dns.Msg
	)

	BeforeEach(func() {
		mockAnswer = new(dns.Msg)
	})

	JustBeforeEach(func() {
		if m == nil {
			m = &mockResolver{}
			m.On("Resolve", mock.Anything).Return(&model.Response{
				Res:    mockAnswer,
				RType:  model.ResponseTypeCUSTOMDNS,
				Reason: "Test",
			}, nil)
		}

		sut = NewEdeResolver(sutConfig).(*EdeResolver)
		sut.Next(m)
	})

	When("ede is disabled", func() {
		BeforeEach(func() {
			sutConfig = config.EdeConfig{
				Enable: false,
			}
		})
		It("shouldn't add EDE information", func() {
			resp, err := sut.Resolve(newRequest("example.com", dns.Type(dns.TypeA)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.RType).Should(Equal(model.ResponseTypeCUSTOMDNS))
			Expect(resp.Res.Answer).Should(BeEmpty())
			Expect(resp.Res.Extra).Should(BeEmpty())

			// delegated to next resolver
			Expect(m.Calls).Should(HaveLen(1))
		})
	})

	When("ede is enabled", func() {
		BeforeEach(func() {
			sutConfig = config.EdeConfig{
				Enable: true,
			}
		})
		It("should add EDE information", func() {
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

		When("resolver returns an error", func() {
			resolveErr := errors.New("test")

			BeforeEach(func() {
				m = &mockResolver{}
				m.On("Resolve", mock.Anything).Return(nil, resolveErr)
			})

			It("should return it", func() {
				resp, err := sut.Resolve(newRequest("example.com", dns.Type(dns.TypeA)))
				Expect(resp).To(BeNil())
				Expect(err).To(Equal(resolveErr))
			})
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			BeforeEach(func() {
				sutConfig = config.EdeConfig{Enable: true}
			})
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(c).Should(Equal(configEnabled))
			})
		})

		When("resolver is disabled", func() {
			BeforeEach(func() {
				sutConfig = config.EdeConfig{Enable: false}
			})
			It("should return 'disabled'", func() {
				c := sut.Configuration()
				Expect(c).Should(ContainElement(configStatusDisabled))
			})
		})
	})
})
