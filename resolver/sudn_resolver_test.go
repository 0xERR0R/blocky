package resolver

import (
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("SudnResolver", Label("sudnResolver"), func() {
	var (
		sut *SpecialUseDomainNamesResolver
		m   *mockResolver
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		mockAnswer, err := util.NewMsgWithAnswer("example.com.", 300, A, "123.145.123.145")
		Expect(err).Should(Succeed())

		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)

		sut = NewSpecialUseDomainNamesResolver().(*SpecialUseDomainNamesResolver)
		sut.Next(m)
	})

	Describe("IsEnabled", func() {
		It("is true", func() {
			Expect(sut.IsEnabled()).Should(BeTrue())
		})
	})

	Describe("LogConfig", func() {
		It("should not log anything", func() {
			logger, hook := log.NewMockEntry()

			sut.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
		})
	})

	Describe("Blocking special names", func() {
		It("should block arpa", func() {
			for _, arpa := range sudnArpaSlice() {
				Expect(sut.Resolve(newRequest(arpa, A))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeSPECIAL),
							HaveReturnCode(dns.RcodeNameError),
							HaveReason("Special-Use Domain Name"),
						))
			}
		})

		It("should block test", func() {
			Expect(sut.Resolve(newRequest(sudnTest, A))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeSPECIAL),
						HaveReturnCode(dns.RcodeNameError),
						HaveReason("Special-Use Domain Name"),
					))
		})

		It("should block invalid", func() {
			Expect(sut.Resolve(newRequest(sudnInvalid, A))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeSPECIAL),
						HaveReturnCode(dns.RcodeNameError),
						HaveReason("Special-Use Domain Name"),
					))
		})

		It("should block localhost none A", func() {
			Expect(sut.Resolve(newRequest(sudnLocalhost, HTTPS))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeSPECIAL),
						HaveReturnCode(dns.RcodeNameError),
						HaveReason("Special-Use Domain Name"),
					))
		})

		It("should block local", func() {
			Expect(sut.Resolve(newRequest(mdnsLocal, A))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeSPECIAL),
						HaveReturnCode(dns.RcodeNameError),
						HaveReason("Special-Use Domain Name"),
					))
		})

		It("should block localhost none A", func() {
			Expect(sut.Resolve(newRequest(mdnsLocal, HTTPS))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeSPECIAL),
						HaveReturnCode(dns.RcodeNameError),
						HaveReason("Special-Use Domain Name"),
					))
		})
	})

	Describe("Resolve localhost", func() {
		It("should resolve IPv4 loopback", func() {
			Expect(sut.Resolve(newRequest(sudnLocalhost, A))).
				Should(
					SatisfyAll(
						BeDNSRecord(sudnLocalhost, A, sut.defaults.loopbackV4.String()),
						HaveTTL(BeNumerically("==", 0)),
						HaveResponseType(ResponseTypeSPECIAL),
						HaveReturnCode(dns.RcodeSuccess),
					))
		})

		It("should resolve IPv6 loopback", func() {
			Expect(sut.Resolve(newRequest(sudnLocalhost, AAAA))).
				Should(
					SatisfyAll(
						BeDNSRecord(sudnLocalhost, AAAA, sut.defaults.loopbackV6.String()),
						HaveTTL(BeNumerically("==", 0)),
						HaveResponseType(ResponseTypeSPECIAL),
						HaveReturnCode(dns.RcodeSuccess),
					))
		})
	})

	Describe("Forward other", func() {
		It("should forward example.com", func() {
			Expect(sut.Resolve(newRequest("example.com", A))).
				Should(
					SatisfyAll(
						BeDNSRecord("example.com.", A, "123.145.123.145"),
						HaveTTL(BeNumerically("==", 300)),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))
		})
	})
})
