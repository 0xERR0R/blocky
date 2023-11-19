// Description: Tests for ede_resolver.go
package resolver

import (
	"context"
	"errors"
	"math"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"

	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("EdeResolver", func() {
	var (
		sut        *EDEResolver
		sutConfig  config.EDE
		m          *mockResolver
		mockAnswer *dns.Msg

		ctx      context.Context
		cancelFn context.CancelFunc
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

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

		sut = NewEDEResolver(sutConfig)
		sut.Next(m)
	})

	When("ede is disabled", func() {
		BeforeEach(func() {
			sutConfig = config.EDE{
				Enable: false,
			}
		})
		It("shouldn't add EDE information", func() {
			Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeCUSTOMDNS),
						HaveReturnCode(dns.RcodeSuccess),
						Not(HaveEdnsOption(dns.EDNS0EDE)),
					))

			// delegated to next resolver
			Expect(m.Calls).Should(HaveLen(1))
		})

		Describe("IsEnabled", func() {
			It("is false", func() {
				Expect(sut.IsEnabled()).Should(BeFalse())
			})
		})
	})

	When("ede is enabled", func() {
		BeforeEach(func() {
			sutConfig = config.EDE{
				Enable: true,
			}
		})

		extractEdeOption := func(res *Response) dns.EDNS0_EDE {
			return *util.GetEdns0Option[*dns.EDNS0_EDE](res.Res)
		}

		It("should add EDE information", func() {
			Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeCUSTOMDNS),
						HaveReturnCode(dns.RcodeSuccess),
						HaveEdnsOption(dns.EDNS0EDE),
						WithTransform(extractEdeOption,
							SatisfyAll(
								HaveField("InfoCode", Equal(dns.ExtendedErrorCodeForgedAnswer)),
								HaveField("ExtraText", Equal("Test")),
							)),
					))
		})

		When("resolver returns other", func() {
			BeforeEach(func() {
				m = &mockResolver{}
				m.On("Resolve", mock.Anything).Return(&Response{
					Res:    mockAnswer,
					RType:  ResponseType(math.MaxInt),
					Reason: "Test",
				}, nil)
			})

			It("shouldn't add EDE information", func() {
				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveReturnCode(dns.RcodeSuccess),
							Not(HaveEdnsOption(dns.EDNS0EDE)),
						))

				// delegated to next resolver
				Expect(m.Calls).Should(HaveLen(1))
			})
		})

		When("resolver returns an error", func() {
			resolveErr := errors.New("test")

			BeforeEach(func() {
				m = &mockResolver{}
				m.On("Resolve", mock.Anything).Return(nil, resolveErr)
			})

			It("should return it", func() {
				resp, err := sut.Resolve(ctx, newRequest("example.com", A))
				Expect(resp).To(BeNil())
				Expect(err).To(Equal(resolveErr))
			})
		})

		Describe("LogConfig", func() {
			It("should log something", func() {
				logger, hook := log.NewMockEntry()

				sut.LogConfig(logger)

				Expect(hook.Calls).ShouldNot(BeEmpty())
			})
		})
	})
})
