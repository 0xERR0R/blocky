package resolver

import (
	"context"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
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
		sut = NewFilteringResolver(sutConfig)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)
		sut.Next(m)
	})

	Describe("IsEnabled", func() {
		It("is false", func() {
			Expect(sut.IsEnabled()).Should(BeFalse())
		})
	})

	Describe("LogConfig", func() {
		It("should log something", func() {
			logger, hook := log.NewMockEntry()

			sut.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
		})
	})

	When("Filtering query types are defined", func() {
		BeforeEach(func() {
			sutConfig = config.FilteringConfig{
				QueryTypes: config.NewQTypeSet(AAAA, MX),
			}
		})
		It("Should delegate to next resolver if request query has other type", func() {
			Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			// delegated to next resolver
			Expect(m.Calls).Should(HaveLen(1))
		})
		It("Should return empty answer for defined query type", func() {
			Expect(sut.Resolve(ctx, newRequest("example.com.", AAAA))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeFILTERED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			// no call of next resolver
			Expect(m.Calls).Should(BeZero())
		})
	})

	When("No filtering query types are defined", func() {
		BeforeEach(func() {
			sutConfig = config.FilteringConfig{}
		})
		It("Should return empty answer without error", func() {
			Expect(sut.Resolve(ctx, newRequest("example.com.", AAAA))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			// delegated to next resolver
			Expect(m.Calls).Should(HaveLen(1))
		})
	})
})
