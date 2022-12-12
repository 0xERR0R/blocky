package resolver

import (
	"errors"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"

	. "github.com/0xERR0R/blocky/model"

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
			m.On("Resolve", mock.Anything).Return(&Response{
				Res:    mockAnswer,
				RType:  ResponseTypeCUSTOMDNS,
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
			Expect(sut.Resolve(newRequest("example.com.", A))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeCUSTOMDNS),
						HaveReturnCode(dns.RcodeSuccess),
						WithTransform(ToExtra, BeEmpty()),
					))

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

		extractFirstOptRecord := func(e []dns.RR) []dns.EDNS0 {
			return e[0].(*dns.OPT).Option
		}

		It("should add EDE information", func() {
			Expect(sut.Resolve(newRequest("example.com.", A))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeCUSTOMDNS),
						HaveReturnCode(dns.RcodeSuccess),
						// extra should contain one OPT record
						WithTransform(ToExtra,
							SatisfyAll(
								HaveLen(1),
								WithTransform(extractFirstOptRecord,
									SatisfyAll(
										ContainElement(HaveField("InfoCode", Equal(dns.ExtendedErrorCodeForgedAnswer))),
										ContainElement(HaveField("ExtraText", Equal("Test"))),
									)),
							)),
					))
		})

		When("resolver returns an error", func() {
			resolveErr := errors.New("test")

			BeforeEach(func() {
				m = &mockResolver{}
				m.On("Resolve", mock.Anything).Return(nil, resolveErr)
			})

			It("should return it", func() {
				resp, err := sut.Resolve(newRequest("example.com", A))
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
