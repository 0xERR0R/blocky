package resolver

import (
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/resolver/dnssec"
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

			// RFC 8914: the SERVFAIL says why validation failed. The answer is below the root
			// trust anchor, and what the lookup of the root DNSKEY RRset gets decides the reason:
			// keys is the reply to it, or nil for none.
			DescribeTable("tells the client why validation failed with an extended DNS error",
				func(keys *dns.Msg, code uint16, text string) {
					mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: response}, nil).Once()

					if keys == nil {
						mockUpstream.On("Resolve", mock.Anything).Return(nil, errors.New("i/o timeout"))
					} else {
						mockUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: keys}, nil)
					}

					resp, err := sut.Resolve(ctx, request)
					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeServerFailure))
					Expect(resp.Res.Answer).Should(BeEmpty())
					Expect(resp.RType).Should(Equal(model.ResponseTypeBOGUS))
					Expect(resp.Reason).Should(Equal("DNSSEC validation failed: " + text))
					// The metric label names the kind of failure, and no name of the query
					Expect(resp.ReasonLabel).Should(Equal("DNSSEC validation failed: " + dns.ExtendedErrorCodeToString[code]))

					ede := util.GetEdns0Option[*dns.EDNS0_EDE](resp.Res)
					Expect(ede).ShouldNot(BeNil())
					Expect(ede.InfoCode).Should(Equal(code))
					Expect(ede.ExtraText).Should(Equal(resp.Reason))
				},
				Entry("No Reachable Authority for a lookup without reply",
					(*dns.Msg)(nil), dns.ExtendedErrorCodeNoReachableAuthority, "no reply to the DNSKEY query for ."),
				Entry("Network Error for a truncated reply",
					&dns.Msg{Truncated: true}, dns.ExtendedErrorCodeNetworkError, "truncated reply to the DNSKEY query for ."),
				Entry("DNSKEY Missing for a server failure",
					&dns.Msg{Rcode: dns.RcodeServerFailure}, dns.ExtendedErrorCodeDNSKEYMissing,
					"SERVFAIL reply to the DNSKEY query for ."),
				Entry("DNSKEY Missing for a reply without the keys",
					&dns.Msg{}, dns.ExtendedErrorCodeDNSKEYMissing,
					"no records of the DNSKEY RRset in the reply to the DNSKEY query for ."),
			)

			// Regression for #2126 and the follow-up review: after the GHSA-x845 hardening an
			// unsigned answer under the (default) root trust anchor is classified bogus -> SERVFAIL.
			// Only public-upstream answers (RESOLVED, and cached upstream answers re-served as
			// CACHED) carry a chain of trust in the public DNS hierarchy and form the GHSA-x845
			// attack surface, so we validate exactly those. Trusted-local / synthesized answers
			// - conditional-upstream private zones, special-use names like localhost, DNS64-
			// synthesized AAAA - are inherently unsigned and must be exempted (like the rebinding
			// resolver's response-type whitelist) instead of being turned into SERVFAIL.
			DescribeTable("skips validation for trusted-local / synthesized responses (whitelist carve-out)",
				func(rType model.ResponseType) {
					// unsigned answer; the local resolver may even assert AD, which we must not propagate
					response.AuthenticatedData = true
					mockUpstream.On("Resolve", mock.Anything).Return(
						&model.Response{Res: response, RType: rType}, nil)

					resp, err := sut.Resolve(ctx, request)
					Expect(err).Should(Succeed())
					// passes through untouched - not turned into SERVFAIL
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(HaveLen(1))
					Expect(resp.RType).Should(Equal(rType))
					// AD cleared: we did not authenticate it
					Expect(resp.Res.AuthenticatedData).Should(BeFalse())
					// the carve-out short-circuits before the validator runs, so no DS/DNSKEY
					// sub-queries are issued - only the initial next.Resolve hit the upstream
					Expect(mockUpstream.Calls).Should(HaveLen(1))
				},
				Entry("conditional upstream - private/split-horizon zone (#2126)", model.ResponseTypeCONDITIONAL),
				Entry("special-use domain name - e.g. localhost", model.ResponseTypeSPECIAL),
				Entry("DNS64-synthesized AAAA", model.ResponseTypeSYNTHESIZED),
			)

			// The GHSA-x845 attack surface - public-upstream answers - must remain fully
			// validated, including cached upstream answers re-served as CACHED (re-validated on
			// every cache hit). The whitelist carve-out above is strictly response-type scoped
			// and must not weaken this.
			DescribeTable("still validates (SERVFAIL) unsigned public-upstream responses (GHSA-x845 preserved)",
				func(rType model.ResponseType) {
					mockUpstream.On("Resolve", mock.Anything).Return(
						&model.Response{Res: response, RType: rType}, nil)

					resp, err := sut.Resolve(ctx, request)
					Expect(err).Should(Succeed())
					// unsigned answer under the default root anchor -> bogus -> SERVFAIL
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeServerFailure))
				},
				Entry("resolved - public upstream", model.ResponseTypeRESOLVED),
				Entry("cached upstream answer - re-validated on hit", model.ResponseTypeCACHED),
			)

			// RRSIG records have no RRSIG of their own, so nothing can validate the answer to a query
			// for them. Unbound does not validate such an answer either (needs_validation).
			It("returns the answer to a query for RRSIG records without validating it", func() {
				request.Req = util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeRRSIG))
				rrsig := func(owner string) dns.RR {
					return &dns.RRSIG{
						Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
						TypeCovered: dns.TypeA, Algorithm: dns.ECDSAP256SHA256, Labels: 2, OrigTtl: 300,
						KeyTag: 12345, SignerName: "example.com.", Signature: "invalid",
					}
				}
				alias, _ := util.NewMsgWithAnswer("example.com.", 300, CNAME, "target.example.com.")
				other, _ := util.NewMsgWithAnswer("example.com.", 300, A, "192.0.2.1")

				// The RRSIG records of the query name, those of the name that its CNAME leads to, and
				// an answer section that holds neither
				answers := [][]dns.RR{
					{rrsig("example.com.")},
					{alias.Answer[0], rrsig("target.example.com.")},
					other.Answer,
				}
				for _, answer := range answers {
					res := &dns.Msg{Answer: answer}
					res.AuthenticatedData = true

					mockUpstream.On("Resolve", mock.Anything).Return(
						&model.Response{Res: res, RType: model.ResponseTypeRESOLVED}, nil).Once()
				}
				mockUpstream.On("Resolve", mock.Anything).Return(
					&model.Response{Res: new(dns.Msg), RType: model.ResponseTypeRESOLVED}, nil)

				for i, answer := range answers {
					resp, err := sut.Resolve(ctx, request)
					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(Equal(answer))
					Expect(resp.Res.AuthenticatedData).Should(BeFalse())
					Expect(mockUpstream.Calls).Should(HaveLen(i+1), "no DS or DNSKEY query")
				}

				// A reply without answer is validated: it is a denial, which nothing proves here, so
				// it is bogus under the root anchor
				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeServerFailure))
			})

			// RFC 4035 §3.2.2: with CD set, the client validates itself and gets the data as is.
			When("the client sets the CD bit", func() {
				BeforeEach(func() {
					request.Req.CheckingDisabled = true
				})

				DescribeTable("returns the upstream answer without validating it",
					func(rType model.ResponseType) {
						// unsigned answer under the default root anchor: bogus without CD
						response.AuthenticatedData = true
						mockUpstream.On("Resolve", mock.Anything).Return(
							&model.Response{Res: response, RType: rType}, nil)

						resp, err := sut.Resolve(ctx, request)
						Expect(err).Should(Succeed())
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(resp.Res.Answer).Should(HaveLen(1))
						Expect(resp.RType).Should(Equal(rType))
						Expect(resp.Res.AuthenticatedData).Should(BeFalse())
						// no DS/DNSKEY sub-queries, and the CD bit went upstream with the request
						Expect(mockUpstream.Calls).Should(HaveLen(1))
						forwarded, ok := mockUpstream.Calls[0].Arguments.Get(0).(*model.Request)
						Expect(ok).Should(BeTrue())
						Expect(forwarded.Req.CheckingDisabled).Should(BeTrue())
					},
					Entry("resolved - public upstream", model.ResponseTypeRESOLVED),
					Entry("cached upstream answer", model.ResponseTypeCACHED),
				)

				It("returns data with a broken signature instead of SERVFAIL", func() {
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
						Expiration:  uint32(time.Now().Add(-48 * time.Hour).Unix()),
						Inception:   uint32(time.Now().Add(-72 * time.Hour).Unix()),
						KeyTag:      12345,
						SignerName:  "example.com.",
						Signature:   "invalid",
					})
					mockUpstream.On("Resolve", mock.Anything).Return(
						&model.Response{Res: response, RType: model.ResponseTypeRESOLVED}, nil)

					resp, err := sut.Resolve(ctx, request)
					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(HaveLen(2))
					Expect(resp.Res.AuthenticatedData).Should(BeFalse())
				})
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

			response := createServFailResponseDNSSEC(modelReq, dns.ExtendedErrorCodeDNSBogus, reason)

			Expect(response).ShouldNot(BeNil())
			Expect(response.Res.Rcode).Should(Equal(dns.RcodeServerFailure))
			Expect(response.Reason).Should(Equal(reason))
			// a validation failure is an error, not a block: it must not be counted
			// as one in the statistics, nor reported to the client as EDE "Blocked"
			Expect(response.RType).Should(Equal(model.ResponseTypeBOGUS))
			Expect(response.RType.ToExtendedErrorCode()).Should(Equal(dns.ExtendedErrorCodeDNSBogus))

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

			response := createServFailResponseDNSSEC(modelReq, dns.ExtendedErrorCodeDNSBogus, "test reason")

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

		When("the answer is authentic", func() {
			// example.com. is the trust anchor and signs its records
			var (
				key    *dns.DNSKEY
				signed func(rr dns.RR) []dns.RR
			)

			newRR := func(s string) dns.RR {
				rr, err := dns.NewRR(s)
				Expect(err).Should(Succeed())

				return rr
			}
			// sent returns rr, which example.com. signed with its TTL, and its RRSIG with the TTL that
			// the upstream sends for them
			sent := func(ttl uint32, rr dns.RR) []dns.RR {
				rrs := signed(rr)
				for _, rr := range rrs {
					rr.Header().Ttl = ttl
				}

				return rrs
			}
			ttls := func(rrs []dns.RR) []uint32 {
				out := make([]uint32, len(rrs))
				for i, rr := range rrs {
					out[i] = rr.Header().Ttl
				}

				return out
			}

			BeforeEach(func() {
				key = &dns.DNSKEY{
					Hdr:   dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
					Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256,
				}

				priv, err := key.Generate(256)
				for err == nil && key.KeyTag() == 0 { // RRSIG.Sign refuses key tag 0
					priv, err = key.Generate(256)
				}
				Expect(err).Should(Succeed())

				signed = func(rr dns.RR) []dns.RR {
					sig := &dns.RRSIG{
						Algorithm: key.Algorithm, KeyTag: key.KeyTag(), SignerName: key.Hdr.Name,
						Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
						Expiration: uint32(time.Now().Add(time.Hour).Unix()),
					}
					Expect(sig.Sign(priv.(crypto.Signer), []dns.RR{rr})).Should(Succeed())

					return []dns.RR{rr, sig}
				}

				sutConfig.TrustAnchors = []string{key.String()}
			})

			It("takes the RRSIG records that cover no RRset of their section from the reply", func() {
				// The answer section holds the RRSIG of an AAAA RRset that it does not hold, and the
				// authority section that of an NS RRset that it does not hold
				mockUpstream.On("Resolve", mock.Anything)
				mockUpstream.ResolveFn = func(_ context.Context, req *model.Request) (*model.Response, error) {
					res := new(dns.Msg)
					if req.Req.Question[0].Qtype == dns.TypeDNSKEY {
						res.Answer = signed(key)
					} else {
						res.Answer = append(signed(newRR("example.com. 300 IN A 192.0.2.1")),
							signed(newRR("example.com. 300 IN AAAA 2001:db8::1"))[1])
						res.Ns = signed(newRR("example.com. 300 IN NS ns.example.com."))[1:]
					}

					return &model.Response{Res: res, RType: model.ResponseTypeRESOLVED}, nil
				}

				resp, err := sut.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", A)})
				Expect(err).Should(Succeed())
				Expect(resp.Res.AuthenticatedData).Should(BeTrue())
				Expect(resp.Res.Answer).Should(HaveLen(2))
				Expect(resp.Res.Answer[1].(*dns.RRSIG).TypeCovered).Should(Equal(dns.TypeA))
				Expect(resp.Res.Ns).Should(BeEmpty())

				// A reply that is not validated stays as it is
				unchecked := util.NewMsgWithQuestion("example.com.", A)
				unchecked.CheckingDisabled = true

				resp, err = sut.Resolve(ctx, &model.Request{Req: unchecked})
				Expect(err).Should(Succeed())
				Expect(resp.Res.AuthenticatedData).Should(BeFalse())
				Expect(resp.Res.Answer).Should(HaveLen(3))
				Expect(resp.Res.Ns).Should(HaveLen(1))
			})

			It("takes the NS RRset without RRSIG, which validation leaves out, from the authority section", func() {
				mockUpstream.On("Resolve", mock.Anything)
				mockUpstream.ResolveFn = func(_ context.Context, req *model.Request) (*model.Response, error) {
					res := new(dns.Msg)
					if req.Req.Question[0].Qtype == dns.TypeDNSKEY {
						res.Answer = signed(key)
					} else {
						res.Answer = signed(newRR("example.com. 300 IN A 192.0.2.1"))
						res.Ns = []dns.RR{newRR("example.com. 300 IN NS ns.example.com.")}
					}

					return &model.Response{Res: res, RType: model.ResponseTypeRESOLVED}, nil
				}

				resp, err := sut.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", A)})
				Expect(err).Should(Succeed())
				Expect(resp.Res.AuthenticatedData).Should(BeTrue())
				Expect(resp.Res.Answer).Should(HaveLen(2))
				Expect(resp.Res.Ns).Should(BeEmpty())

				// A reply that is not validated stays as it is
				unchecked := util.NewMsgWithQuestion("example.com.", A)
				unchecked.CheckingDisabled = true

				resp, err = sut.Resolve(ctx, &model.Request{Req: unchecked})
				Expect(err).Should(Succeed())
				Expect(resp.Res.AuthenticatedData).Should(BeFalse())
				Expect(resp.Res.Ns).Should(HaveLen(1))
			})

			It("takes the additional records but the OPT record from the reply (RFC 4035 §3.2.3)", func() {
				// The additional section holds the address of the mail exchanger, which nothing signs
				mockUpstream.On("Resolve", mock.Anything)
				mockUpstream.ResolveFn = func(_ context.Context, req *model.Request) (*model.Response, error) {
					res := new(dns.Msg)
					if req.Req.Question[0].Qtype == dns.TypeDNSKEY {
						res.Answer = signed(key)
					} else {
						res.Answer = signed(newRR("example.com. 300 IN MX 10 mail.example.com."))
						res.Extra = []dns.RR{newRR("mail.example.com. 300 IN A 192.0.2.25")}
						res.SetEdns0(ednsUDPSize, true)
					}

					return &model.Response{Res: res, RType: model.ResponseTypeRESOLVED}, nil
				}

				resp, err := sut.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeMX))})
				Expect(err).Should(Succeed())
				Expect(resp.Res.AuthenticatedData).Should(BeTrue())
				Expect(resp.Res.Answer).Should(HaveLen(2))
				Expect(resp.Res.Extra).Should(HaveLen(1))
				Expect(resp.Res.IsEdns0()).ShouldNot(BeNil())

				// A reply that is not validated stays as it is
				unchecked := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeMX))
				unchecked.CheckingDisabled = true

				resp, err = sut.Resolve(ctx, &model.Request{Req: unchecked})
				Expect(err).Should(Succeed())
				Expect(resp.Res.AuthenticatedData).Should(BeFalse())
				Expect(resp.Res.Extra).Should(HaveLen(2))
			})

			It("leaves no RRset of the reply a TTL beyond what its RRSIG lets it have (RFC 4035 §5.3.3)", func() {
				// The upstream sends a day for an RRset that the zone signed with five minutes, and two
				// minutes for one that it signed with ten
				reply := &dns.Msg{
					Answer: sent(86400, newRR("example.com. 300 IN A 192.0.2.1")),
					Ns:     sent(120, newRR("example.com. 600 IN NS ns.example.com.")),
				}
				keys := &dns.Msg{Answer: sent(300, key)}

				mockUpstream.On("Resolve", mock.Anything)
				mockUpstream.ResolveFn = func(_ context.Context, req *model.Request) (*model.Response, error) {
					if req.Req.Question[0].Qtype == dns.TypeDNSKEY {
						return &model.Response{Res: keys, RType: model.ResponseTypeRESOLVED}, nil
					}

					// Every reply holds the same records
					res := *reply

					return &model.Response{Res: &res, RType: model.ResponseTypeRESOLVED}, nil
				}

				resp, err := sut.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", A)})
				Expect(err).Should(Succeed())
				Expect(resp.Res.AuthenticatedData).Should(BeTrue())
				Expect(ttls(resp.Res.Answer)).Should(Equal([]uint32{300, 300}))
				Expect(ttls(resp.Res.Ns)).Should(Equal([]uint32{120, 120}))

				// A reply that is not validated stays as it is, and so do the records of one that is
				unchecked := util.NewMsgWithQuestion("example.com.", A)
				unchecked.CheckingDisabled = true

				resp, err = sut.Resolve(ctx, &model.Request{Req: unchecked})
				Expect(err).Should(Succeed())
				Expect(resp.Res.AuthenticatedData).Should(BeFalse())
				Expect(ttls(resp.Res.Answer)).Should(Equal([]uint32{86400, 86400}))
			})

			It("bounds both delivery and cache reuse by the signed TTL despite a higher cache minimum", func() {
				cache, err := NewCachingResolver(ctx, config.Caching{MinCachingTime: config.Duration(time.Hour)}, sutConfig, nil)
				Expect(err).Should(Succeed())

				cache.Next(mockUpstream)
				sut.Next(cache)

				reply := &dns.Msg{Answer: sent(300, newRR("example.com. 300 IN A 192.0.2.1"))}
				keys := &dns.Msg{Answer: sent(300, key)}
				asked := 0

				mockUpstream.On("Resolve", mock.Anything)
				mockUpstream.ResolveFn = func(_ context.Context, req *model.Request) (*model.Response, error) {
					if req.Req.Question[0].Qtype == dns.TypeDNSKEY {
						return &model.Response{Res: keys, RType: model.ResponseTypeRESOLVED}, nil
					}

					asked++

					return &model.Response{Res: reply.Copy(), RType: model.ResponseTypeRESOLVED}, nil
				}

				// The cache answers the second query, and the reply is validated again
				for range 2 {
					resp, err := sut.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", A)})
					Expect(err).Should(Succeed())
					Expect(resp.Res.AuthenticatedData).Should(BeTrue())
					Expect(ttls(resp.Res.Answer)).Should(HaveLen(2))
					for _, ttl := range ttls(resp.Res.Answer) {
						Expect(ttl).Should(BeNumerically("~", 300, 1))
						Expect(ttl).Should(BeNumerically("<=", 300))
					}
				}

				Expect(asked).Should(Equal(1))

				held, err := cache.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", A)})
				Expect(err).Should(Succeed())
				Expect(held.RType).Should(Equal(model.ResponseTypeCACHED))

				for _, ttl := range ttls(held.Res.Answer) {
					Expect(ttl).Should(BeNumerically(">", 0))
					Expect(ttl).Should(BeNumerically("<=", 300))
				}
			})
		})

		// A reply that fails validation says that the reply is bad, not that the name is. Before the
		// client gets SERVFAIL the question is asked once more, and what validation says of the
		// second reply stands.
		//
		// example.com. is the trust anchor and signs its records, and unsigned.example.com. is a
		// delegation of it without DS RRset. The upstream sends the replies to a question in the
		// order of replies and those to the DNSKEY query in the order of keys, the last of them
		// every further time, and no reply for nil.
		When("a reply fails validation", func() {
			var (
				key           *dns.DNSKEY
				signed        func(rr dns.RR) []dns.RR
				a             dns.RR
				replies, keys []*dns.Msg
				asked         map[uint16]int // How often the upstream was asked, by query type
				request       *model.Request
			)

			newRR := func(s string) dns.RR {
				rr, err := dns.NewRR(s)
				Expect(err).Should(Succeed())

				return rr
			}
			// told returns the extended DNS error of resp, which must be a SERVFAIL for a Bogus reply
			told := func(resp *model.Response) *dns.EDNS0_EDE {
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeServerFailure))
				Expect(resp.RType).Should(Equal(model.ResponseTypeBOGUS))

				ede := util.GetEdns0Option[*dns.EDNS0_EDE](resp.Res)
				Expect(ede).ShouldNot(BeNil())

				return ede
			}
			// resolve returns what the client of request gets
			resolve := func() *model.Response {
				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())

				return resp
			}
			// kept returns the failure that the cache of validation failures holds for request, and the
			// time that is left of its entry
			kept := func() (*validationFailure, time.Duration) {
				return sut.failureCache.Get(failureCacheKey(request, "", nil))
			}
			// leave lets the time of that entry pass until left is left of it: failureMemory when the
			// refusal of its query has just ended
			leave := func(left time.Duration) {
				failure, _ := kept()
				Expect(failure).ShouldNot(BeNil())

				sut.failureCache.Put(failureCacheKey(request, "", nil), failure, left)
			}

			BeforeEach(func() {
				key = &dns.DNSKEY{
					Hdr:   dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
					Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256,
				}

				priv, err := key.Generate(256)
				for err == nil && key.KeyTag() == 0 { // RRSIG.Sign refuses key tag 0
					priv, err = key.Generate(256)
				}
				Expect(err).Should(Succeed())

				signed = func(rr dns.RR) []dns.RR {
					sig := &dns.RRSIG{
						Hdr:       dns.RR_Header{Ttl: rr.Header().Ttl},
						Algorithm: key.Algorithm, KeyTag: key.KeyTag(), SignerName: key.Hdr.Name,
						Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
						Expiration: uint32(time.Now().Add(time.Hour).Unix()),
					}
					Expect(sig.Sign(priv.(crypto.Signer), []dns.RR{rr})).Should(Succeed())

					return []dns.RR{rr, sig}
				}

				sutConfig.TrustAnchors = []string{key.String()}

				a = newRR("example.com. 300 IN A 192.0.2.1")
				keys = []*dns.Msg{{Answer: signed(key)}}
				asked = map[uint16]int{}
				request = &model.Request{Req: util.NewMsgWithQuestion("example.com.", A)}
				noDS := &dns.Msg{Ns: signed(newRR("unsigned.example.com. 300 IN NSEC www.example.com. NS RRSIG NSEC"))}

				mockUpstream.On("Resolve", mock.Anything)
				mockUpstream.ResolveFn = func(_ context.Context, req *model.Request) (*model.Response, error) {
					qtype := req.Req.Question[0].Qtype
					asked[qtype]++

					from := &replies

					switch qtype {
					case dns.TypeDNSKEY:
						from = &keys
					case dns.TypeDS:
						from = &[]*dns.Msg{noDS}
					}

					reply := (*from)[0]
					if len(*from) > 1 {
						*from = (*from)[1:]
					}

					if reply == nil {
						return nil, errors.New("i/o timeout")
					}

					return &model.Response{Res: reply.Copy(), RType: model.ResponseTypeRESOLVED}, nil
				}
			})

			It("asks once more, and answers with the second reply if that is authentic", func() {
				replies = []*dns.Msg{{Answer: []dns.RR{a}}, {Answer: signed(a)}}

				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Res.AuthenticatedData).Should(BeTrue())
				Expect(resp.Res.Answer).Should(HaveLen(2))
				Expect(asked[dns.TypeA]).Should(Equal(2))
				Expect(sut.failureCache.TotalCount()).Should(Equal(0), "one failed reply does not make a failure to keep")
			})

			It("answers SERVFAIL with the extended error of the second validation if both replies fail", func() {
				// The first reply has no RRSIG, and the RRSIG of the second is that of other data
				forged := []dns.RR{newRR("example.com. 300 IN A 203.0.113.66"), signed(a)[1]}
				replies = []*dns.Msg{{Answer: []dns.RR{a}}, {Answer: forged}, {Answer: signed(a)}}

				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(told(resp).InfoCode).Should(Equal(dns.ExtendedErrorCodeDNSBogus))
				Expect(resp.Reason).Should(Equal("DNSSEC validation failed: example.com. A failed validation"))
				Expect(asked[dns.TypeA]).Should(Equal(2), "the question is not asked a third time")
			})

			It("answers SERVFAIL with the extended error of the first validation without a second reply", func() {
				replies = []*dns.Msg{{Answer: []dns.RR{a}}, nil, {Answer: []dns.RR{a}}}

				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(told(resp).InfoCode).Should(Equal(dns.ExtendedErrorCodeRRSIGsMissing))
				Expect(asked[dns.TypeA]).Should(Equal(2))

				// The question has failed twice, like one whose second reply failed: it is refused with
				// the same error, and not asked
				resp, err = sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(told(resp).InfoCode).Should(Equal(dns.ExtendedErrorCodeRRSIGsMissing))
				Expect(asked[dns.TypeA]).Should(Equal(2))
			})

			It("validates the second reply without what the first validation found wrong with its zone", func() {
				// The DNSKEY reply comes without its RRSIG once, which makes example.com. Bogus for the
				// first validation. The validation of the second reply asks for the keys again.
				keys = []*dns.Msg{{Answer: []dns.RR{key}}, {Answer: signed(key)}}
				replies = []*dns.Msg{{Answer: signed(a)}}

				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(resp.Res.AuthenticatedData).Should(BeTrue())
				Expect(asked).Should(Equal(map[uint16]int{dns.TypeA: 2, dns.TypeDNSKEY: 2}))
			})

			It("asks the upstream, not the cache below, which then holds the second reply", func() {
				cache, err := NewCachingResolver(ctx, config.Caching{}, sutConfig, nil)
				Expect(err).Should(Succeed())

				cache.Next(mockUpstream)
				sut.Next(cache)

				// The cache holds a reply before it is validated: here the first one, without RRSIG
				replies = []*dns.Msg{{Answer: []dns.RR{a}}, {Answer: signed(a)}}

				for range 2 {
					resp, err := sut.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", A)})
					Expect(err).Should(Succeed())
					Expect(resp.Res.AuthenticatedData).Should(BeTrue())
					Expect(resp.Res.Answer).Should(HaveLen(2))
				}

				Expect(asked[dns.TypeA]).Should(Equal(2), "the cache answers the second query")
			})

			// RFC 4035 §4.7, RFC 9520 §3.2 and §3.4: a question whose replies failed validation twice
			// goes to the cache of validation failures. Until its refusal ends, its clients get the
			// failure that was kept, and nothing is asked or validated for it.
			DescribeTable("refuses a question that failed twice without asking, for a second the first time",
				func(cached bool) {
					if cached {
						cache, err := NewCachingResolver(ctx, config.Caching{}, sutConfig, nil)
						Expect(err).Should(Succeed())

						cache.Next(mockUpstream)
						sut.Next(cache)
					}

					// The first reply has no RRSIG, and the RRSIG of the second is that of other data. A
					// third reply would be authentic.
					forged := []dns.RR{newRR("example.com. 300 IN A 203.0.113.66"), signed(a)[1]}
					replies = []*dns.Msg{{Answer: []dns.RR{a}}, {Answer: forged}, {Answer: signed(a)}}

					// Three client queries, however they spell the name, reach the upstream twice, and
					// each is told what the second validation said
					var query *model.Request

					for _, name := range []string{"example.com.", "example.com.", "Example.COM."} {
						query = &model.Request{Req: util.NewMsgWithQuestion(name, A)}

						resp, err := sut.Resolve(ctx, query)
						Expect(err).Should(Succeed())
						Expect(told(resp).InfoCode).Should(Equal(dns.ExtendedErrorCodeDNSBogus))
						Expect(resp.Reason).Should(Equal("DNSSEC validation failed: example.com. A failed validation"))
					}

					Expect(asked[dns.TypeA]).Should(Equal(2))
					Expect(sut.failureCache.TotalCount()).Should(Equal(1))

					// The cache keeps the failure for the second of its refusal and for the time after it
					// in which a further failure counts as one that follows it
					key := failureCacheKey(query, "", nil)
					failure, left := sut.failureCache.Get(key)
					Expect(failure.refused).Should(Equal(time.Second))
					Expect(left).Should(BeNumerically("~", time.Second+failureMemory, time.Second))

					// When the refusal has ended, the question is asked and validated again: by the cache
					// below, which holds the second reply, and then by the upstream, or by the upstream
					sut.failureCache.Put(key, failure, failureMemory)

					resp, err := sut.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", A)})
					Expect(err).Should(Succeed())
					Expect(resp.Res.AuthenticatedData).Should(BeTrue())
					Expect(asked[dns.TypeA]).Should(Equal(3))

					// The reply validated: the cache holds no failure of the question any longer
					Expect(sut.failureCache.TotalCount()).Should(Equal(0))
				},
				Entry("with a cache below, which holds a reply that failed", true),
				Entry("without a cache", false),
			)

			// The second ask is for a reply that came and failed validation. A DS or DNSKEY lookup that
			// got no reply was tried as often as the upstream resolver tries (RFC 9520 §3.1): the
			// question is not asked again, and the failure is kept from the first (RFC 9520 §3.2).
			It("does not ask again when a lookup of the validation got no reply, and refuses the query", func() {
				// The reply is authentic, and the upstream fails the first query for the keys of its zone
				replies = []*dns.Msg{{Answer: signed(a)}}
				keys = []*dns.Msg{nil, {Answer: signed(key)}}
				once := map[uint16]int{dns.TypeA: 1, dns.TypeDNSKEY: 1}

				ede := told(resolve())
				Expect(ede.InfoCode).Should(Equal(dns.ExtendedErrorCodeNoReachableAuthority))
				Expect(ede.ExtraText).Should(ContainSubstring("no reply to the DNSKEY query for example.com."))
				Expect(asked).Should(Equal(once))

				// The query is refused for its second with that error, and nothing is asked for it
				failure, left := kept()
				Expect(failure.refused).Should(Equal(time.Second))
				Expect(left).Should(BeNumerically("~", time.Second+failureMemory, time.Second))

				Expect(told(resolve()).InfoCode).Should(Equal(dns.ExtendedErrorCodeNoReachableAuthority))
				Expect(asked).Should(Equal(once))

				// After it the query is asked again. The lookup is answered, and the reply validates.
				leave(failureMemory)

				Expect(resolve().Res.AuthenticatedData).Should(BeTrue())
				Expect(asked).Should(Equal(map[uint16]int{dns.TypeA: 2, dns.TypeDNSKEY: 2}))
				Expect(sut.failureCache.TotalCount()).Should(Equal(0))
			})

			It("asks again when a lookup of the validation got a reply that does not answer it", func() {
				// The reply is authentic, and the upstream answers every query for the keys of its zone
				// with a server failure. Each validation makes that lookup twice.
				replies = []*dns.Msg{{Answer: signed(a)}}
				keys = []*dns.Msg{{Rcode: dns.RcodeServerFailure}}

				ede := told(resolve())
				Expect(ede.InfoCode).Should(Equal(dns.ExtendedErrorCodeDNSKEYMissing))
				Expect(ede.ExtraText).Should(ContainSubstring("SERVFAIL reply to the DNSKEY query for example.com."))
				Expect(asked).Should(Equal(map[uint16]int{dns.TypeA: 2, dns.TypeDNSKEY: 4}))
				Expect(sut.failureCache.TotalCount()).Should(Equal(1))
			})
			// A lookup ends without a reply also when its first try got a reply that does not answer it
			// and its second try got none
			It("does not ask again when the second try of a lookup got no reply", func() {
				// The reply is authentic. The upstream answers the first query for the keys of its zone
				// with a server failure, and fails the second.
				replies = []*dns.Msg{{Answer: signed(a)}}
				keys = []*dns.Msg{{Rcode: dns.RcodeServerFailure}, nil, {Answer: signed(key)}}

				ede := told(resolve())
				Expect(ede.InfoCode).Should(Equal(dns.ExtendedErrorCodeNoReachableAuthority))
				Expect(ede.ExtraText).Should(ContainSubstring("no reply to the DNSKEY query for example.com."))
				Expect(asked).Should(Equal(map[uint16]int{dns.TypeA: 1, dns.TypeDNSKEY: 2}))

				failure, _ := kept()
				Expect(failure.refused).Should(Equal(time.Second))
			})

			// Whatever the verdict rests on: a second ask would make the lookup again that got no reply.
			// www.sub.example.com. A has an RRSIG of each of two zones. That of example.com. is the RRSIG
			// of other data. That of sub.example.com. cannot be tried, as the query for the DS RRset of
			// that zone gets no reply.
			It("does not ask again when a lookup for one signer got no reply and the RRSIG of another fails", func() {
				sub := &dns.DNSKEY{
					Hdr:   dns.RR_Header{Name: "sub.example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
					Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256,
				}

				subPriv, err := sub.Generate(256)
				for err == nil && sub.KeyTag() == 0 { // RRSIG.Sign refuses key tag 0
					subPriv, err = sub.Generate(256)
				}
				Expect(err).Should(Succeed())

				host := newRR("www.sub.example.com. 300 IN A 192.0.2.1")
				bySub := &dns.RRSIG{
					Hdr:       dns.RR_Header{Ttl: 300},
					Algorithm: sub.Algorithm, KeyTag: sub.KeyTag(), SignerName: sub.Hdr.Name,
					Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
					Expiration: uint32(time.Now().Add(time.Hour).Unix()),
				}
				Expect(bySub.Sign(subPriv.(crypto.Signer), []dns.RR{host})).Should(Succeed())

				ofOtherData := signed(newRR("www.sub.example.com. 300 IN A 203.0.113.66"))[1]

				// A second reply would be authentic for a validator that does not look for sub.example.com.
				replies = []*dns.Msg{{Answer: []dns.RR{host, ofOtherData, bySub}}, {Answer: signed(host)}}
				request.Req = util.NewMsgWithQuestion("www.sub.example.com.", A)

				upstream := mockUpstream.ResolveFn
				mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
					if req.Req.Question[0].Qtype == dns.TypeDS {
						asked[dns.TypeDS]++

						return nil, errors.New("i/o timeout")
					}

					return upstream(ctx, req)
				}

				// The verdict tells of the RRSIG that failed, and the question is not asked again
				ede := told(resolve())
				Expect(ede.InfoCode).Should(Equal(dns.ExtendedErrorCodeDNSBogus))
				Expect(ede.ExtraText).Should(ContainSubstring("www.sub.example.com. A failed validation"))
				Expect(asked).Should(Equal(map[uint16]int{dns.TypeA: 1, dns.TypeDS: 1, dns.TypeDNSKEY: 1}))

				failure, _ := kept()
				Expect(failure.refused).Should(Equal(time.Second))
			})
			// RFC 9520 §3.2: "Resolvers SHOULD employ an exponential or linear backoff algorithm to
			// increase the cache duration for persistent resolution failures."
			It("refuses a query for twice as long each time that it fails again, and for a minute at most", func() {
				replies = []*dns.Msg{{Answer: []dns.RR{a}}} // Every reply fails validation

				for row, refused := range []time.Duration{
					time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second,
					dnssec.BogusTTL, dnssec.BogusTTL,
				} {
					// The query is asked twice, and is then refused without being asked
					for range 2 {
						told(resolve())
						Expect(asked[dns.TypeA]).Should(Equal(2 * (row + 1)))
					}

					failure, left := kept()
					Expect(failure.refused).Should(Equal(refused))
					Expect(left).Should(BeNumerically("~", refused+failureMemory, time.Second))

					// Its refusal ends, and the failure is remembered
					leave(failureMemory)
				}
			})

			// The queries of clients that fail at one time are no row of failures: each of them was
			// asked when the cache held what it held for the others
			It("counts the failures of a query that fail at one time as one", func() {
				replies = []*dns.Msg{{Answer: []dns.RR{a}}} // Every reply fails validation

				// While the second reply to the query is on its way, the query of another client fails
				// twice, and is kept
				upstream, others, other := mockUpstream.ResolveFn, 0, false
				mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
					if req.AskedAgain && req.Req.Question[0].Qtype == dns.TypeA && !other {
						other = true
						others++

						resp, err := sut.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", A)})
						Expect(err).Should(Succeed())
						told(resp)

						other = false
					}

					return upstream(ctx, req)
				}

				for _, refused := range []time.Duration{time.Second, 2 * time.Second} {
					told(resolve())

					failure, left := kept()
					Expect(failure.refused).Should(Equal(refused))
					Expect(left).Should(BeNumerically("~", refused+failureMemory, time.Second))

					leave(failureMemory)
				}

				Expect(others).Should(Equal(2))
				Expect(asked[dns.TypeA]).Should(Equal(8))
			})

			// RFC 9520 §3.2: nothing is sent for a query that matches a cached failure. That holds for
			// its second ask too: a failure that the query of another client left in the meantime answers
			// it, and stays as it is.
			It("refuses the second ask of a query that failed for another client in the meantime", func() {
				// The replies to the query of the other client have the RRSIG of other data. The first
				// reply to the query has no RRSIG, and a second one would be authentic.
				forged := []dns.RR{newRR("example.com. 300 IN A 203.0.113.66"), signed(a)[1]}
				replies = []*dns.Msg{{Answer: forged}, {Answer: forged}, {Answer: []dns.RR{a}}, {Answer: signed(a)}}

				// While the first reply is on its way, the query of the other client fails twice, and is kept
				var (
					theirs *validationFailure
					left   time.Duration
				)

				upstream, other := mockUpstream.ResolveFn, false
				mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
					if req.Req.Question[0].Qtype == dns.TypeA && !other {
						other = true

						resp, err := sut.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", A)})
						Expect(err).Should(Succeed())
						Expect(told(resp).InfoCode).Should(Equal(dns.ExtendedErrorCodeDNSBogus))

						theirs, left = kept()
					}

					return upstream(ctx, req)
				}

				// The query is answered with the failure of the other client, and not asked again
				Expect(told(resolve()).InfoCode).Should(Equal(dns.ExtendedErrorCodeDNSBogus))
				Expect(asked[dns.TypeA]).Should(Equal(3))

				// Nothing is kept for it: the entry and its time are those of the other client
				failure, now := kept()
				Expect(failure).Should(BeIdenticalTo(theirs))
				Expect(failure.refused).Should(Equal(time.Second))
				Expect(now).Should(BeNumerically("<=", left))
			})

			// A row of failures ends with a reply to the query that validates, and with the time for
			// which the cache remembers a failure: the failure that follows is a first one
			DescribeTable("takes a failure of a query for a first one again",
				func(end func()) {
					replies = []*dns.Msg{{Answer: []dns.RR{a}}} // Every reply fails validation

					for range 2 {
						told(resolve())
						leave(failureMemory)
					}

					failure, _ := kept()
					Expect(failure.refused).Should(Equal(2 * time.Second))

					end()

					replies = []*dns.Msg{{Answer: []dns.RR{a}}}

					told(resolve())

					failure, _ = kept()
					Expect(failure.refused).Should(Equal(time.Second))
				},
				Entry("after a reply that validated", func() {
					replies = []*dns.Msg{{Answer: signed(a)}}

					Expect(resolve().Res.AuthenticatedData).Should(BeTrue())
					Expect(asked[dns.TypeA]).Should(Equal(5))
				}),
				Entry("after a second reply that validated", func() {
					replies = []*dns.Msg{{Answer: []dns.RR{a}}, {Answer: signed(a)}}

					Expect(resolve().Res.AuthenticatedData).Should(BeTrue())
					Expect(asked[dns.TypeA]).Should(Equal(6))
				}),
				Entry("after a reply that validated for another client while the query was asked", func() {
					upstream, other := mockUpstream.ResolveFn, false
					mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
						if req.Req.Question[0].Qtype == dns.TypeA && !other {
							other = true
							replies = []*dns.Msg{{Answer: signed(a)}, {Answer: []dns.RR{a}}}

							resp, err := sut.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", A)})
							Expect(err).Should(Succeed())
							Expect(resp.Res.AuthenticatedData).Should(BeTrue())
						}

						return upstream(ctx, req)
					}
				}),
				Entry("when the cache remembers the last one no longer", func() {
					leave(time.Millisecond)
					Eventually(func() time.Duration {
						_, left := kept()

						return left
					}).Should(BeNumerically("<=", 0))
				}),
			)

			// A reply that validates, whatever its result, ends the row of failures of its query (see
			// validated): it removes the failure that the cache held for the query when the query was
			// asked. It removes no other: not the failure of another query, and not one that the query of
			// another client leaves while this one is asked.
			DescribeTable("removes for a reply that validates the failure that the cache held for its query, and no other",
				func(name string, answer func() []dns.RR) {
					_, logger := sut.log(ctx)
					validates := func() *askedQuery {
						q := new(askedQuery)

						resp, err := sut.answer(ctx, logger, request, q)
						Expect(err).Should(Succeed())
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))

						return q
					}
					failure := &validationFailure{refused: time.Second}

					request.Req = util.NewMsgWithQuestion(name, A)
					replies = []*dns.Msg{{Answer: answer()}}

					// The cache holds a failure of another query, the one for the name with RD clear
					other := &model.Request{Req: request.Req.Copy()}
					other.Req.RecursionDesired = false
					sut.failureCache.Put(failureCacheKey(other, "", nil), failure, failureMemory)

					Expect(validates().last).Should(BeNil())
					Expect(sut.failureCache.TotalCount()).Should(Equal(1))

					// The cache holds a failure of the query too, one whose refusal has ended
					sut.failureCache.Put(failureCacheKey(request, "", nil), failure, failureMemory)
					Expect(sut.failureCache.TotalCount()).Should(Equal(2))

					Expect(validates().last).Should(Equal(failure))
					Expect(sut.failureCache.TotalCount()).Should(Equal(1))

					_, left := sut.failureCache.Get(failureCacheKey(other, "", nil))
					Expect(left).Should(BeNumerically(">", 0))

					// The cache holds no failure of the query when the query is asked, and one when its reply
					// has come, which the query of another client left: it stays
					upstream := mockUpstream.ResolveFn
					mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
						if req.Req.Question[0].Qtype == dns.TypeA {
							sut.failureCache.Put(failureCacheKey(request, "", nil), failure, failureMemory)
						}

						return upstream(ctx, req)
					}

					Expect(validates().last).Should(BeNil())
					Expect(sut.failureCache.TotalCount()).Should(Equal(2))
				},
				Entry("Secure", "example.com.", func() []dns.RR { return signed(a) }),
				Entry("Insecure", "www.unsigned.example.com.",
					func() []dns.RR { return []dns.RR{newRR("www.unsigned.example.com. 300 IN A 192.0.2.1")} }),
				Entry("Indeterminate", "example.org.",
					func() []dns.RR { return []dns.RR{newRR("example.org. 300 IN A 192.0.2.1")} }),
			)

			// The upstream gets the message of the client, so a query in another form gets another
			// reply: a failure is kept for the queries in the form of the one that failed
			// (RFC 4035 §4.7: the cache is no means to deny service).
			DescribeTable("refuses a query that failed twice, and no query for its name in another form",
				func(change func(query *dns.Msg), same bool) {
					// Both replies to the first query fail validation, and the next one is authentic
					replies = []*dns.Msg{{Answer: []dns.RR{a}}, {Answer: []dns.RR{a}}, {Answer: signed(a)}}

					first := util.NewMsgWithQuestion("example.com.", A)
					change(first)

					resp, err := sut.Resolve(ctx, &model.Request{Req: first})
					Expect(err).Should(Succeed())
					Expect(told(resp).InfoCode).Should(Equal(dns.ExtendedErrorCodeRRSIGsMissing))
					Expect(asked[dns.TypeA]).Should(Equal(2))
					Expect(sut.failureCache.TotalCount()).Should(Equal(1))

					// The query that a client ordinarily sends for the name
					resp, err = sut.Resolve(ctx, request)
					Expect(err).Should(Succeed())

					if same {
						Expect(told(resp).InfoCode).Should(Equal(dns.ExtendedErrorCodeRRSIGsMissing))
						Expect(asked[dns.TypeA]).Should(Equal(2))
					} else {
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(resp.Res.AuthenticatedData).Should(BeTrue())
						Expect(asked[dns.TypeA]).Should(Equal(3))
					}
				},
				Entry("the same query", func(*dns.Msg) {}, true),
				Entry("RD clear", func(query *dns.Msg) { query.RecursionDesired = false }, false),
				Entry("another class", func(query *dns.Msg) { query.Question[0].Qclass = dns.ClassCHAOS }, false),
				Entry("another EDNS version", func(query *dns.Msg) {
					query.SetEdns0(ednsUDPSize, true)
					query.IsEdns0().SetVersion(1)
				}, false),
				Entry("an EDNS option", func(query *dns.Msg) {
					query.SetEdns0(ednsUDPSize, true)
					query.IsEdns0().Option = append(query.IsEdns0().Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
				}, false),
			)

			It("forms the key of a query only when the cache of validation failures needs it", func() {
				_, logger := sut.log(ctx)

				// A reply that validates, while the cache is empty
				replies = []*dns.Msg{{Answer: signed(a)}}
				valid := new(askedQuery)

				resp, err := sut.answer(ctx, logger, request, valid)
				Expect(err).Should(Succeed())
				Expect(resp.Res.AuthenticatedData).Should(BeTrue())
				Expect(valid.key).Should(BeEmpty())

				// A query that fails twice is kept under its key
				replies = []*dns.Msg{{Answer: []dns.RR{a}}}
				failing := new(askedQuery)

				resp, err = sut.answer(ctx, logger, request, failing)
				Expect(err).Should(Succeed())
				told(resp)
				Expect(failing.key).Should(HaveLen(sha256.Size))

				_, left := sut.failureCache.Get(failing.key)
				Expect(left).Should(BeNumerically(">", 0))

				// While the cache holds an entry, a query is looked up by its key
				next := new(askedQuery)

				resp, err = sut.answer(ctx, logger, request, next)
				Expect(err).Should(Succeed())
				told(resp)
				Expect(next.key).Should(Equal(failing.key))
			})

			It("names a query by a digest that the client subnet set below does not change", func() {
				subnet := func(address string) *dns.EDNS0_SUBNET {
					return &dns.EDNS0_SUBNET{
						Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP(address).To4(),
					}
				}
				query := func(options ...dns.EDNS0) *model.Request {
					msg := util.NewMsgWithQuestion("example.com.", A)
					msg.SetEdns0(ednsUDPSize, true)
					msg.IsEdns0().Option = options

					return &model.Request{Req: msg}
				}

				// The key is as long for a message of some kilobytes as for one of some octets
				plain := failureCacheKey(query(), "", nil)
				Expect(plain).Should(HaveLen(sha256.Size))
				Expect(failureCacheKey(query(&dns.EDNS0_PADDING{Padding: make([]byte, 4000)}), "", nil)).
					Should(And(HaveLen(sha256.Size), Not(Equal(plain))))

				// A query that came without the option, and gets one from a resolver below
				Expect(failureCacheKey(query(subnet("192.0.2.0")), "", nil)).Should(Equal(plain))

				// A query that came with the option, whatever a resolver below makes of it
				sent := subnet("198.51.100.0")
				with := failureCacheKey(query(sent), "", sent)
				Expect(with).ShouldNot(Equal(plain))
				Expect(failureCacheKey(query(subnet("192.0.2.0")), "", sent)).Should(Equal(with))
				Expect(failureCacheKey(query(), "", sent)).Should(Equal(with))

				// Another upstream group has its own entries
				Expect(failureCacheKey(query(), "group", nil)).ShouldNot(Equal(plain))
			})

			It("refuses nothing from the cache of validation failures to a client that sets the CD bit", func() {
				// Every reply fails validation
				replies = []*dns.Msg{{Answer: []dns.RR{a}}}

				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(told(resp).InfoCode).Should(Equal(dns.ExtendedErrorCodeRRSIGsMissing))
				Expect(asked[dns.TypeA]).Should(Equal(2))

				// RFC 4035 §3.2.2: the client validates itself, and gets the data as it is
				unchecked := util.NewMsgWithQuestion("example.com.", A)
				unchecked.CheckingDisabled = true

				resp, err = sut.Resolve(ctx, &model.Request{Req: unchecked})
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Res.Answer).Should(HaveLen(1))
				Expect(asked[dns.TypeA]).Should(Equal(3))
			})

			It("asks again for every query if the cache below cannot hold the second reply", func() {
				cache, err := NewCachingResolver(ctx, config.Caching{}, sutConfig, nil)
				Expect(err).Should(Succeed())

				cache.Next(mockUpstream)
				sut.Next(cache)

				// The second reply has a TTL of zero: the cache keeps the first, which fails
				replies = []*dns.Msg{{Answer: []dns.RR{a}}, {Answer: signed(newRR("example.com. 0 IN A 192.0.2.1"))}}

				for range 2 {
					resp, err := sut.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", A)})
					Expect(err).Should(Succeed())
					Expect(resp.Res.AuthenticatedData).Should(BeTrue())
				}

				Expect(asked[dns.TypeA]).Should(Equal(3), "the cache answers first, and the upstream when asked again")
			})

			// A known interaction: the cache below gives an answer that DNS64 made back as a cached
			// upstream answer. It has no RRSIG, so for a name of a signed zone it fails validation.
			// Asked again, the question goes past the cache, and DNS64 makes the answer anew.
			It("asks again for an answer of DNS64 that the cache below holds, which is made anew", func() {
				cache, err := NewCachingResolver(ctx, config.Caching{}, sutConfig, nil)
				Expect(err).Should(Succeed())

				dns64 := NewDNS64Resolver(config.DNS64{Enable: true})

				sut.Next(cache)
				cache.Next(dns64)
				dns64.Next(mockUpstream)

				// example.com. has an A RRset and no AAAA RRset, which its NSEC record proves
				replies = []*dns.Msg{{Answer: signed(a)}}
				noData := &dns.Msg{Ns: slices.Concat(
					signed(newRR("example.com. 300 IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 300")),
					signed(newRR("example.com. 300 IN NSEC unsigned.example.com. A NS SOA RRSIG NSEC DNSKEY")))}
				resolve := mockUpstream.ResolveFn
				mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
					if req.Req.Question[0].Qtype != dns.TypeAAAA {
						return resolve(ctx, req)
					}

					asked[dns.TypeAAAA]++

					return &model.Response{Res: noData.Copy(), RType: model.ResponseTypeRESOLVED}, nil
				}

				for range 3 {
					resp, err := sut.Resolve(ctx, &model.Request{Req: util.NewMsgWithQuestion("example.com.", AAAA)})
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(model.ResponseTypeSYNTHESIZED))
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(HaveLen(1))
					Expect(resp.Res.AuthenticatedData).Should(BeFalse())
				}

				Expect(asked).Should(Equal(map[uint16]int{dns.TypeAAAA: 3, dns.TypeA: 3, dns.TypeDNSKEY: 1}))
			})

			It("does not ask again for a reply whose validation ran out of a budget, as it does for another", func() {
				// A CNAME chain with more signed links than a validation verifies signatures
				const links = 128

				name := func(i int) string { return fmt.Sprintf("h%d.example.com.", i) }
				chain := signed(newRR(name(links) + " 300 IN A 192.0.2.1"))

				for i := range links {
					chain = append(chain, signed(newRR(name(i)+" 300 IN CNAME "+name(i+1)))...)
				}

				replies = []*dns.Msg{{Answer: chain}}
				request.Req = util.NewMsgWithQuestion(name(0), A)

				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(told(resp).ExtraText).Should(ContainSubstring("more signature verifications"))
				Expect(asked[dns.TypeA]).Should(Equal(1))

				// Its first link with another target, which the RRSIG does not verify, is asked for again
				forged := []dns.RR{newRR(name(0) + " 300 IN CNAME elsewhere.example.com."), chain[3]}
				replies = []*dns.Msg{{Answer: forged}}
				request.Req = util.NewMsgWithQuestion(name(0), A)

				resp, err = sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(told(resp).InfoCode).Should(Equal(dns.ExtendedErrorCodeDNSBogus))
				Expect(asked[dns.TypeA]).Should(Equal(3))

				// A resolver that may make one upstream query for a validation has none left for the DS
				// RRset of the delegation
				sutConfig.MaxUpstreamQueries = 1
				frugal, err := NewDNSSECResolver(ctx, sutConfig, mockUpstream)
				Expect(err).Should(Succeed())

				frugal.Next(mockUpstream)

				replies = []*dns.Msg{{Answer: []dns.RR{newRR("www.unsigned.example.com. 300 IN A 192.0.2.1")}}}
				request.Req = util.NewMsgWithQuestion("www.unsigned.example.com.", A)

				resp, err = frugal.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(told(resp).ExtraText).Should(ContainSubstring("no upstream query left"))
				Expect(asked[dns.TypeA]).Should(Equal(4))
			})

			It("keeps no failure of a second reply whose validation ran out of a budget", func() {
				// A CNAME chain with more signed links than a validation verifies signatures
				const links = 128

				name := func(i int) string { return fmt.Sprintf("h%d.example.com.", i) }
				chain := signed(newRR(name(links) + " 300 IN A 192.0.2.1"))

				for i := range links {
					chain = append(chain, signed(newRR(name(i)+" 300 IN CNAME "+name(i+1)))...)
				}

				// The first reply is its first link with another target, which the RRSIG does not
				// verify. The second is the chain: one client query has one budget.
				forged := []dns.RR{newRR(name(0) + " 300 IN CNAME elsewhere.example.com."), chain[3]}
				replies = []*dns.Msg{{Answer: forged}, {Answer: chain}}
				request.Req = util.NewMsgWithQuestion(name(0), A)

				resp, err := sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(told(resp).ExtraText).Should(ContainSubstring("more signature verifications"))
				Expect(asked[dns.TypeA]).Should(Equal(2))
				Expect(sut.failureCache.TotalCount()).Should(Equal(0))

				// So the next query is asked
				resp, err = sut.Resolve(ctx, request)
				Expect(err).Should(Succeed())
				Expect(told(resp).ExtraText).Should(ContainSubstring("more signature verifications"))
				Expect(asked[dns.TypeA]).Should(Equal(3))
			})

			DescribeTable("asks once for a reply that validation does not refuse",
				func(answer func() []dns.RR, authentic bool) {
					replies = []*dns.Msg{{Answer: answer()}, nil}
					request.Req = util.NewMsgWithQuestion(replies[0].Answer[0].Header().Name, A)

					resp, err := sut.Resolve(ctx, request)
					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).ShouldNot(BeEmpty())
					Expect(resp.Res.AuthenticatedData).Should(Equal(authentic))
					Expect(asked[dns.TypeA]).Should(Equal(1))
				},
				Entry("Secure", func() []dns.RR { return signed(a) }, true),
				Entry("Insecure: below the delegation without DS RRset",
					func() []dns.RR { return []dns.RR{newRR("www.unsigned.example.com. 300 IN A 192.0.2.1")} }, false),
				Entry("Indeterminate: no trust anchor above the name",
					func() []dns.RR { return []dns.RR{newRR("example.org. 300 IN A 192.0.2.1")} }, false),
			)
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
