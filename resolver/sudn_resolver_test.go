package resolver

import (
	"context"
	"fmt"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("SudnResolver", Label("sudnResolver"), func() {
	var (
		sut       *SpecialUseDomainNamesResolver
		sutConfig config.SUDN
		m         *mockResolver

		ctx      context.Context
		cancelFn context.CancelFunc
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		var err error

		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		sutConfig, err = config.WithDefaults[config.SUDN]()
		Expect(err).Should(Succeed())
	})

	JustBeforeEach(func() {
		mockAnswer, err := util.NewMsgWithAnswer("example.com.", 300, A, "123.145.123.145")
		Expect(err).Should(Succeed())

		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)

		sut = NewSpecialUseDomainNamesResolver(sutConfig)
		sut.Next(m)
	})

	Describe("handlers", func() {
		It("should have correct response type", func() {
			for domain, handler := range sudnHandlers {
				resp, err := sut.Resolve(ctx, newRequest(domain, A))
				Expect(err).Should(Succeed())

				if handler == nil {
					Expect(resp).ShouldNot(HaveResponseType(ResponseTypeSPECIAL))

					continue
				}

				Expect(resp).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeSPECIAL),
							HaveReason("Special-Use Domain Name"),
						))
			}
		})
	})

	Describe("Resolve", func() {
		//nolint:unparam // linter thinks `qName` is always `A` because of "RFC 6762 Appendix G" table
		entry := func(qType dns.Type, qName string, expectedRCode int, extraMatchers ...any) TableEntry {
			GinkgoHelper()

			var verb string
			switch expectedRCode {
			case dns.RcodeSuccess:
				verb = "resolve"
			case dns.RcodeNameError:
				verb = "block"
			}

			description := fmt.Sprintf("should %s %s IN %s", verb, qName, qType)

			args := []any{qType, qName, expectedRCode}
			args = append(args, extraMatchers...)

			return Entry(description, args...)
		}

		DescribeTable("handled domains",
			func(qType dns.Type, qName string, expectedRCode int, extraMatchers ...types.GomegaMatcher) {
				resp, err := sut.Resolve(ctx, newRequest(qName, qType))
				Expect(err).Should(Succeed())
				Expect(resp).Should(SatisfyAll(
					HaveResponseType(ResponseTypeSPECIAL),
					HaveReason("Special-Use Domain Name"),
					HaveReturnCode(expectedRCode),
				))

				switch expectedRCode {
				case dns.RcodeSuccess:
					Expect(resp).Should(HaveTTL(BeNumerically("==", 0)))
				case dns.RcodeNameError:
					Expect(resp).Should(HaveNoAnswer())
				}

				Expect(resp).Should(SatisfyAll(extraMatchers...))
			},

			entry(A, "1.0.0.10.in-addr.arpa.", dns.RcodeNameError),
			entry(A, "something.test.", dns.RcodeNameError),
			entry(A, "something.localhost.", dns.RcodeSuccess, BeDNSRecord("something.localhost.", A, loopbackV4.String())),
			entry(AAAA, "thing.localhost.", dns.RcodeSuccess, BeDNSRecord("thing.localhost.", AAAA, loopbackV6.String())),
			entry(HTTPS, "something.localhost.", dns.RcodeNameError),
			entry(A, "something.invalid.", dns.RcodeNameError),
			entry(A, "something.local.", dns.RcodeNameError),
			entry(HTTPS, "something.local.", dns.RcodeNameError),
			entry(A, "1.0.254.169.in-addr.arpa.", dns.RcodeNameError),
			entry(A, "something.intranet.", dns.RcodeNameError),
			entry(A, "something.internal.", dns.RcodeNameError),
			entry(A, "something.private.", dns.RcodeNameError),
			entry(A, "something.corp.", dns.RcodeNameError),
			entry(A, "something.home.", dns.RcodeNameError),
			entry(A, "something.lan.", dns.RcodeNameError),
			entry(A, "something.onion.", dns.RcodeNameError),
		)

		When("RFC 6762 Appendix G is disabled", func() {
			BeforeEach(func() {
				sutConfig.RFC6762AppendixG = false
			})

			DescribeTable("",
				func(qType dns.Type, qName string, expectedRCode int) {
					resp, err := sut.Resolve(ctx, newRequest(qName, qType))
					Expect(err).Should(Succeed())
					Expect(resp).Should(HaveReturnCode(expectedRCode))
					Expect(resp).ShouldNot(HaveResponseType(ResponseTypeSPECIAL))
				},

				entry(A, "something.intranet.", dns.RcodeSuccess),
				entry(A, "something.intranet.", dns.RcodeSuccess),
				entry(A, "something.internal.", dns.RcodeSuccess),
				entry(A, "something.private.", dns.RcodeSuccess),
				entry(A, "something.corp.", dns.RcodeSuccess),
				entry(A, "something.home.", dns.RcodeSuccess),
				entry(A, "something.lan.", dns.RcodeSuccess),
			)
		})

		It("should forward example.com", func() {
			Expect(sut.Resolve(ctx, newRequest("example.com", A))).
				Should(
					SatisfyAll(
						BeDNSRecord("example.com.", A, "123.145.123.145"),
						HaveTTL(BeNumerically("==", 300)),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))
		})

		It("should forward home.arpa. IN DS", func() {
			Expect(sut.Resolve(ctx, newRequest("something.home.arpa.", DS))).
				Should(
					SatisfyAll(
						// setup code doesn't care about the question
						BeDNSRecord("example.com.", A, "123.145.123.145"),
						HaveTTL(BeNumerically("==", 300)),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))
		})

		It("should forward non special use domains", func() {
			resp, err := sut.Resolve(ctx, newRequest("something.not-special.", AAAA))
			Expect(err).Should(Succeed())
			Expect(resp).ShouldNot(HaveResponseType(ResponseTypeSPECIAL))
		})
	})
})
