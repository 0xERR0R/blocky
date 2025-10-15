package resolver

import (
	"context"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("ConditionalUpstreamResolver", Label("conditionalResolver"), func() {
	var (
		sut       *ConditionalUpstreamResolver
		sutConfig config.ConditionalUpstream

		m *mockResolver

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

		fbTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
			response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 123, A, "123.124.122.122")

			return response
		})

		otherTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
			response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 250, A, "192.192.192.192")

			return response
		})

		dotTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
			response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 223, A, "168.168.168.168")

			return response
		})

		refuseTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
			response = new(dns.Msg)
			response.Rcode = dns.RcodeRefused
			// question section in response should be empty
			request.Question = make([]dns.Question, 0)

			return response
		})

		sutConfig = config.ConditionalUpstream{
			Mapping: config.ConditionalUpstreamMapping{
				Upstreams: map[string][]config.Upstream{
					"fritz.box":      {fbTestUpstream.Start()},
					"other.box":      {otherTestUpstream.Start()},
					"refused.domain": {refuseTestUpstream.Start()},
					".":              {dotTestUpstream.Start()},
				},
			},
		}
	})

	JustBeforeEach(func() {
		sut, _ = NewConditionalUpstreamResolver(ctx, sutConfig, defaultUpstreamsConfig, systemResolverBootstrap)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("IsEnabled", func() {
		It("is true", func() {
			Expect(sut.IsEnabled()).Should(BeTrue())
		})
	})

	Describe("LogConfig", func() {
		It("should log something", func() {
			logger, hook := log.NewMockEntry()

			sut.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
		})
	})

	Describe("Resolve conditional DNS queries via defined DNS server", func() {
		When("conditional resolver returns error code", func() {
			It("Should be returned without changes", func() {
				Expect(sut.Resolve(ctx, newRequest("refused.domain.", A))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeCONDITIONAL),
							HaveReason("CONDITIONAL"),
							HaveReturnCode(dns.RcodeRefused),
						))

				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
			})
		})
		When("Query is exact equal defined condition in mapping", func() {
			Context("first mapping entry", func() {
				It("Should resolve the IP of conditional DNS", func() {
					Expect(sut.Resolve(ctx, newRequest("fritz.box.", A))).
						Should(
							SatisfyAll(
								BeDNSRecord("fritz.box.", A, "123.124.122.122"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeCONDITIONAL),
								HaveReason("CONDITIONAL"),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// no call to next resolver
					Expect(m.Calls).Should(BeEmpty())
				})
			})
			Context("last mapping entry", func() {
				It("Should resolve the IP of conditional DNS", func() {
					Expect(sut.Resolve(ctx, newRequest("other.box.", A))).
						Should(
							SatisfyAll(
								BeDNSRecord("other.box.", A, "192.192.192.192"),
								HaveTTL(BeNumerically("==", 250)),
								HaveResponseType(ResponseTypeCONDITIONAL),
								HaveReason("CONDITIONAL"),
								HaveReturnCode(dns.RcodeSuccess),
							))
					// no call to next resolver
					Expect(m.Calls).Should(BeEmpty())
				})
			})
		})
		When("Query is a subdomain of defined condition in mapping", func() {
			It("Should resolve the IP of subdomain", func() {
				Expect(sut.Resolve(ctx, newRequest("test.fritz.box.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("test.fritz.box.", A, "123.124.122.122"),
							HaveTTL(BeNumerically("==", 123)),
							HaveResponseType(ResponseTypeCONDITIONAL),
							HaveReason("CONDITIONAL"),
							HaveReturnCode(dns.RcodeSuccess),
						))
				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
			})
		})
		When("Query is not fqdn and . condition is defined in mapping", func() {
			It("Should resolve the IP of .", func() {
				Expect(sut.Resolve(ctx, newRequest("test.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("test.", A, "168.168.168.168"),
							HaveTTL(BeNumerically("==", 223)),
							HaveResponseType(ResponseTypeCONDITIONAL),
							HaveReason("CONDITIONAL"),
							HaveReturnCode(dns.RcodeSuccess),
						))
				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
			})
		})
	})
	Describe("Delegation to next resolver", func() {
		When("Query doesn't match defined mapping", func() {
			It("should delegate to next resolver", func() {
				Expect(sut.Resolve(ctx, newRequest("google.com.", A))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
				m.AssertExpectations(GinkgoT())
			})
		})
	})

	When("upstream is invalid", func() {
		It("succeeds with bootstrap resolver during construction", func() {
			b := newTestBootstrap(ctx, &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

			upstreamsCfg := defaultUpstreamsConfig
			upstreamsCfg.Init.Strategy = config.InitStrategyFailOnError

			sutConfig := config.ConditionalUpstream{
				Mapping: config.ConditionalUpstreamMapping{
					Upstreams: map[string][]config.Upstream{
						".": {config.Upstream{Host: "example.com"}},
					},
				},
			}

			// Conditional upstreams should always succeed during construction to ensure
			// they remain available even when default upstreams are unreachable.
			// See: https://github.com/0xERR0R/blocky/issues/1639
			r, err := NewConditionalUpstreamResolver(ctx, sutConfig, upstreamsCfg, b)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(r).ShouldNot(BeNil())
		})
	})

	Describe("Domain rewriting", func() {
		BeforeEach(func() {
			sutConfig.Rewrite = map[string]string{
				"source.test": "fritz.box",
			}

			// Recreate resolver with rewrite configuration
			sut, _ = NewConditionalUpstreamResolver(ctx, sutConfig, defaultUpstreamsConfig, systemResolverBootstrap)
			m = &mockResolver{}
			m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
			sut.Next(m)
		})

		When("request matches rewrite rule and conditional mapping", func() {
			It("should rewrite subdomain and resolve via conditional upstream", func() {
				// www.source.test -> www.fritz.box (which has conditional upstream)
				Expect(sut.Resolve(ctx, newRequest("www.source.test.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("www.source.test.", A, "123.124.122.122"),
							HaveTTL(BeNumerically("==", 123)),
							HaveResponseType(ResponseTypeCONDITIONAL),
							HaveReason("CONDITIONAL"),
							HaveReturnCode(dns.RcodeSuccess),
						))

				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
			})

			It("should preserve original domain name in response", func() {
				resp, err := sut.Resolve(ctx, newRequest("www.source.test.", A))
				Expect(err).ShouldNot(HaveOccurred())

				// Question should have original name, not rewritten name
				Expect(resp.Res.Question[0].Name).Should(Equal("www.source.test."))
				// Answer should have original name, not rewritten name
				Expect(resp.Res.Answer[0].Header().Name).Should(Equal("www.source.test."))
			})
		})

		When("request does not match rewrite rule but matches conditional mapping", func() {
			It("should not rewrite and resolve via conditional upstream", func() {
				// Direct request to fritz.box (no rewrite)
				Expect(sut.Resolve(ctx, newRequest("fritz.box.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("fritz.box.", A, "123.124.122.122"),
							HaveTTL(BeNumerically("==", 123)),
							HaveResponseType(ResponseTypeCONDITIONAL),
							HaveReason("CONDITIONAL"),
							HaveReturnCode(dns.RcodeSuccess),
						))

				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
			})
		})
	})
})
