package resolver

import (
	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("FqdnOnlyResolver", func() {
	var (
		sut        *FqdnOnlyResolver
		sutConfig  config.Config
		m          *mockResolver
		mockAnswer *dns.Msg
	)

	BeforeEach(func() {
		mockAnswer = new(dns.Msg)
	})

	JustBeforeEach(func() {
		sut = NewFqdnOnlyResolver(sutConfig)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)
		sut.Next(m)
	})

	When("Fqdn only is enabled", func() {
		BeforeEach(func() {
			sutConfig = config.Config{
				FqdnOnly: true,
			}
		})
		It("Should delegate to next resolver if request query is fqdn", func() {
			Expect(sut.Resolve(newRequest("example.com", A))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			// delegated to next resolver
			Expect(m.Calls).Should(HaveLen(1))
		})
		It("Should return NXDOMAIN if request query is not fqdn", func() {
			Expect(sut.Resolve(newRequest("example", AAAA))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeNOTFQDN),
						HaveReturnCode(dns.RcodeNameError),
					))

			// no call of next resolver
			Expect(m.Calls).Should(BeZero())
		})
		It("Configure should output enabled", func() {
			c := sut.Configuration()
			Expect(c).Should(Equal(configEnabled))
		})
	})

	When("Fqdn only is disabled", func() {
		BeforeEach(func() {
			sutConfig = config.Config{
				FqdnOnly: false,
			}
		})
		It("Should delegate to next resolver if request query is fqdn", func() {
			Expect(sut.Resolve(newRequest("example.com", A))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			// delegated to next resolver
			Expect(m.Calls).Should(HaveLen(1))
		})
		It("Should delegate to next resolver if request query is not fqdn", func() {
			Expect(sut.Resolve(newRequest("example", AAAA))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			// delegated to next resolver
			Expect(m.Calls).Should(HaveLen(1))
		})
		It("Configure should output disabled", func() {
			c := sut.Configuration()
			Expect(c).Should(ContainElement(configStatusDisabled))
		})
	})
})
