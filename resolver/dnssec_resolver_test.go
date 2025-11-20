package resolver

import (
	"context"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("DNSSECResolver", func() {
	var (
		sut          *DNSSECResolver
		sutConfig    config.DNSSEC
		mockUpstream *mockResolver
		ctx          context.Context
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			ctx := context.Background()
			mockUpstream := &mockResolver{}

			sut, _ := NewDNSSECResolver(ctx, config.DNSSEC{Validate: false}, mockUpstream)
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		ctx = context.Background()
		sutConfig = config.DNSSEC{
			Validate: false,
		}
		mockUpstream = &mockResolver{}
	})

	Describe("NewDNSSECResolver", func() {
		When("DNSSEC validation is disabled", func() {
			It("should create resolver without validator", func() {
				resolver, err := NewDNSSECResolver(ctx, sutConfig, mockUpstream)
				Expect(err).Should(Succeed())
				Expect(resolver).ShouldNot(BeNil())

				// Type assert to access validator field
				dnssecResolver, ok := resolver.(*DNSSECResolver)
				Expect(ok).Should(BeTrue())
				Expect(dnssecResolver.validator).Should(BeNil())
			})
		})

		When("DNSSEC validation is enabled", func() {
			BeforeEach(func() {
				sutConfig.Validate = true
			})

			It("should create resolver with validator", func() {
				resolver, err := NewDNSSECResolver(ctx, sutConfig, mockUpstream)
				Expect(err).Should(Succeed())
				Expect(resolver).ShouldNot(BeNil())

				// Type assert to access validator field
				dnssecResolver, ok := resolver.(*DNSSECResolver)
				Expect(ok).Should(BeTrue())
				Expect(dnssecResolver.validator).ShouldNot(BeNil())
			})
		})

		When("custom trust anchors are provided", func() {
			BeforeEach(func() {
				sutConfig.Validate = true
				sutConfig.TrustAnchors = []string{
					". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3",
				}
			})

			It("should create resolver with custom trust anchors", func() {
				resolver, err := NewDNSSECResolver(ctx, sutConfig, mockUpstream)
				Expect(err).Should(Succeed())
				Expect(resolver).ShouldNot(BeNil())

				// Type assert to access validator field
				dnssecResolver, ok := resolver.(*DNSSECResolver)
				Expect(ok).Should(BeTrue())
				Expect(dnssecResolver.validator).ShouldNot(BeNil())
			})
		})

		When("invalid trust anchor is provided", func() {
			BeforeEach(func() {
				sutConfig.Validate = true
				sutConfig.TrustAnchors = []string{
					"invalid trust anchor string",
				}
			})

			It("should return error", func() {
				resolver, err := NewDNSSECResolver(ctx, sutConfig, mockUpstream)
				Expect(err).Should(HaveOccurred())
				Expect(resolver).Should(BeNil())
			})
		})
	})

	Describe("Resolve", func() {
		var (
			request  *model.Request
			response *dns.Msg
		)

		BeforeEach(func() {
			// Create a basic DNS request
			req := util.NewMsgWithQuestion("example.com.", A)
			request = &model.Request{
				Req:      req,
				Protocol: model.RequestProtocolUDP,
			}

			// Create a basic DNS response
			response, _ = util.NewMsgWithAnswer("example.com.", 300, A, "192.0.2.1")
		})

		When("DNSSEC validation is disabled", func() {
			BeforeEach(func() {
				sutConfig.Validate = false
			})

			JustBeforeEach(func() {
				resolver, err := NewDNSSECResolver(ctx, sutConfig, mockUpstream)
				Expect(err).Should(Succeed())

				sut, _ = resolver.(*DNSSECResolver)
				sut.Next(mockUpstream)
			})

			It("should pass through response without modification", func() {
				mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: response}, nil)

				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(resp).ShouldNot(BeNil())
				Expect(resp.Res.Answer).Should(HaveLen(1))
			})

			It("should not set DO bit", func() {
				mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: response}, nil)

				_, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())

				// Verify DO bit was not set
				opt := request.Req.IsEdns0()
				if opt != nil {
					Expect(opt.Do()).Should(BeFalse())
				}
			})
		})

		When("DNSSEC validation is enabled", func() {
			BeforeEach(func() {
				sutConfig.Validate = true
			})

			JustBeforeEach(func() {
				resolver, err := NewDNSSECResolver(ctx, sutConfig, mockUpstream)
				Expect(err).Should(Succeed())

				sut, _ = resolver.(*DNSSECResolver)
				sut.Next(mockUpstream)
			})

			It("should set DO bit on requests", func() {
				mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: response}, nil)

				_, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())

				// Verify DO bit was set
				opt := request.Req.IsEdns0()
				Expect(opt).ShouldNot(BeNil())
				Expect(opt.Do()).Should(BeTrue())
			})

			It("should clear AD flag for insecure responses", func() {
				// Response without DNSSEC records
				response.AuthenticatedData = true // Upstream set it, but we should clear it

				mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: response}, nil)

				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(resp.Res.AuthenticatedData).Should(BeFalse())
			})

			It("should return SERVFAIL when validation is bogus", func() {
				// Response with expired RRSIG
				response.Answer = append(response.Answer, &dns.RRSIG{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeRRSIG,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					TypeCovered: dns.TypeA,
					Algorithm:   8,
					Labels:      2,
					OrigTtl:     300,
					Expiration:  uint32(time.Now().Add(-48 * time.Hour).Unix()), // Expired
					Inception:   uint32(time.Now().Add(-72 * time.Hour).Unix()),
					KeyTag:      12345,
					SignerName:  "example.com.",
					Signature:   "invalid",
				})

				// Mock empty DNSKEY response (missing DNSKEY = Bogus per RFC 4035)
				dnskeyResp := new(dns.Msg)
				dnskeyResp.SetRcode(&dns.Msg{}, dns.RcodeSuccess)
				mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: response}, nil).Once()
				mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: dnskeyResp}, nil)

				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				// Should return SERVFAIL per RFC 4035: RRSIG present + missing DNSKEY = Bogus = SERVFAIL
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeServerFailure))
				Expect(resp.Res.AuthenticatedData).Should(BeFalse())
			})
		})

		When("upstream resolver returns error", func() {
			JustBeforeEach(func() {
				resolver, err := NewDNSSECResolver(ctx, sutConfig, mockUpstream)
				Expect(err).Should(Succeed())

				sut, _ = resolver.(*DNSSECResolver)
				sut.Next(mockUpstream)
			})

			It("should return the error", func() {
				mockUpstream.On("Resolve", mock.Anything).Return(nil, dns.ErrTime)

				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(HaveOccurred())
				Expect(resp).Should(BeNil())
			})
		})
	})

	Describe("LogConfig", func() {
		BeforeEach(func() {
			sutConfig.Validate = false
		})

		JustBeforeEach(func() {
			resolver, err := NewDNSSECResolver(ctx, sutConfig, mockUpstream)
			Expect(err).Should(Succeed())

			sut, _ = resolver.(*DNSSECResolver)
		})

		It("should log configuration", func() {
			logger, hook := log.NewMockEntry()

			sut.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
		})
	})

	Describe("EDNS0 buffer size handling", func() {
		var response *dns.Msg

		BeforeEach(func() {
			sutConfig.Validate = true
			response, _ = util.NewMsgWithAnswer("example.com.", 300, A, "192.0.2.1")
		})

		JustBeforeEach(func() {
			resolver, err := NewDNSSECResolver(ctx, sutConfig, mockUpstream)
			Expect(err).Should(Succeed())

			sut, _ = resolver.(*DNSSECResolver)
			sut.Next(mockUpstream)
		})

		It("should increase EDNS0 buffer size if too small", func() {
			req := util.NewMsgWithQuestion("example.com.", A)
			// Add EDNS0 with small buffer
			req.SetEdns0(512, false)

			request := &model.Request{
				Req:      req,
				Protocol: model.RequestProtocolUDP,
			}

			mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: response}, nil)

			_, err := sut.Resolve(ctx, request)
			Expect(err).Should(Succeed())

			// Verify buffer size was increased
			opt := request.Req.IsEdns0()
			Expect(opt).ShouldNot(BeNil())
			Expect(opt.UDPSize()).Should(BeNumerically(">=", 4096))
			Expect(opt.Do()).Should(BeTrue())
		})

		It("should preserve existing EDNS0 buffer size if adequate", func() {
			req := util.NewMsgWithQuestion("example.com.", A)
			// Add EDNS0 with large buffer
			req.SetEdns0(8192, false)

			request := &model.Request{
				Req:      req,
				Protocol: model.RequestProtocolUDP,
			}

			mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: response}, nil)

			_, err := sut.Resolve(ctx, request)
			Expect(err).Should(Succeed())

			// Verify buffer size was preserved
			opt := request.Req.IsEdns0()
			Expect(opt).ShouldNot(BeNil())
			Expect(opt.UDPSize()).Should(Equal(uint16(8192)))
			Expect(opt.Do()).Should(BeTrue())
		})
	})

	Describe("createServFailResponseDNSSEC", func() {
		It("should create SERVFAIL response with EDE", func() {
			req := util.NewMsgWithQuestion("example.com.", A)
			reason := "DNSSEC validation failed: bogus signatures"
			modelReq := &model.Request{Req: req}

			response := createServFailResponseDNSSEC(modelReq, reason)

			Expect(response).ShouldNot(BeNil())
			Expect(response.Res.Rcode).Should(Equal(dns.RcodeServerFailure))
			Expect(response.Reason).Should(Equal(reason))
			Expect(response.RType).Should(Equal(model.ResponseTypeBLOCKED))

			// Check for EDNS0 with EDE
			opt := response.Res.IsEdns0()
			Expect(opt).ShouldNot(BeNil())

			// Verify EDE option exists
			edeFound := false
			for _, option := range opt.Option {
				if ede, ok := option.(*dns.EDNS0_EDE); ok {
					Expect(ede.InfoCode).Should(Equal(dns.ExtendedErrorCodeDNSBogus))
					Expect(ede.ExtraText).Should(Equal(reason))
					edeFound = true
				}
			}
			Expect(edeFound).Should(BeTrue())
		})

		It("should set proper EDNS0 UDP size", func() {
			req := util.NewMsgWithQuestion("example.com.", A)
			modelReq := &model.Request{Req: req}

			response := createServFailResponseDNSSEC(modelReq, "test reason")

			opt := response.Res.IsEdns0()
			Expect(opt).ShouldNot(BeNil())
			Expect(opt.UDPSize()).Should(Equal(uint16(4096)))
		})
	})

	Describe("Resolve with validation edge cases", func() {
		var response *dns.Msg

		BeforeEach(func() {
			sutConfig.Validate = true
			response, _ = util.NewMsgWithAnswer("example.com.", 300, A, "192.0.2.1")
		})

		JustBeforeEach(func() {
			resolver, err := NewDNSSECResolver(ctx, sutConfig, mockUpstream)
			Expect(err).Should(Succeed())

			sut, _ = resolver.(*DNSSECResolver)
			sut.Next(mockUpstream)
		})

		It("should handle response without question section", func() {
			req := util.NewMsgWithQuestion("example.com.", A)
			request := &model.Request{
				Req:      req,
				Protocol: model.RequestProtocolUDP,
			}

			// Response without question section
			emptyResponse := &dns.Msg{}

			mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: emptyResponse}, nil)

			resp, err := sut.Resolve(ctx, request)
			Expect(err).Should(Succeed())
			Expect(resp).ShouldNot(BeNil())
		})

		It("should handle Secure validation result", func() {
			// This would require a fully valid DNSSEC response chain
			// For now, test that the code path exists
			req := util.NewMsgWithQuestion("example.com.", A)
			request := &model.Request{
				Req:      req,
				Protocol: model.RequestProtocolUDP,
			}

			mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: response}, nil)

			resp, err := sut.Resolve(ctx, request)
			Expect(err).Should(Succeed())
			Expect(resp).ShouldNot(BeNil())
			// AD flag will be cleared for insecure/indeterminate responses
		})

		It("should handle Indeterminate validation result", func() {
			req := util.NewMsgWithQuestion("example.com.", A)
			request := &model.Request{
				Req:      req,
				Protocol: model.RequestProtocolUDP,
			}

			// Response that will be indeterminate
			testResponse, _ := util.NewMsgWithAnswer("example.com.", 300, A, "192.0.2.1")
			testResponse.AuthenticatedData = true

			mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: testResponse}, nil)

			resp, err := sut.Resolve(ctx, request)
			Expect(err).Should(Succeed())
			Expect(resp.Res.AuthenticatedData).Should(BeFalse())
		})
	})
})
