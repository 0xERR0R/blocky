package resolver

import (
	"context"
	"net"
	"net/netip"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("DNS64Resolver", func() {
	var (
		sut        *DNS64Resolver
		sutConfig  config.DNS64
		m          *mockResolver
		ctx        context.Context
		cancelFunc context.CancelFunc
	)

	BeforeEach(func() {
		ctx, cancelFunc = context.WithCancel(context.Background())
		DeferCleanup(cancelFunc)

		sutConfig = config.DNS64{
			Enable:   true,
			Prefixes: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")},
		}
	})

	JustBeforeEach(func() {
		sut = NewDNS64Resolver(sutConfig).(*DNS64Resolver)
		m = &mockResolver{}
		sut.Next(m)
	})

	Describe("Type", func() {
		It("should return correct resolver type", func() {
			Expect(sut.Type()).Should(Equal("dns64"))
		})
	})

	Describe("IsEnabled", func() {
		It("should be enabled when configured", func() {
			Expect(sut.cfg.IsEnabled()).Should(BeTrue())
		})
	})

	Describe("When disabled", func() {
		BeforeEach(func() {
			sutConfig.Enable = false
		})

		It("should pass through all queries without processing when disabled", func() {
			// Test AAAA query that would normally trigger synthesis
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

			// Mock response with no AAAA records (would trigger synthesis if enabled)
			mockResponse := new(dns.Msg)
			mockResponse.SetReply(request)
			mockResponse.Rcode = dns.RcodeSuccess
			// Empty answer section - would trigger A query if DNS64 was enabled

			m.On("Resolve", mock.Anything).Return(&model.Response{Res: mockResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.Res).Should(Equal(mockResponse))
			// Should only call next resolver once (no A query should be made)
			m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
			// Verify it was the AAAA query that was passed through
			m.AssertCalled(GinkgoT(), "Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeAAAA
			}))
		})

		It("should not perform synthesis even with A records available", func() {
			request := util.NewMsgWithQuestion("ipv4only.example.com.", dns.Type(dns.TypeAAAA))

			// Empty AAAA response
			aaaaResponse := new(dns.Msg)
			aaaaResponse.SetReply(request)

			m.On("Resolve", mock.Anything).Return(&model.Response{Res: aaaaResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(BeEmpty())
			// Should NOT query for A records - only one call to next resolver
			m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
			// No synthesis should occur
			Expect(resp.RType).ShouldNot(Equal(model.ResponseTypeSYNTHESIZED))
		})

		It("should pass through A queries unchanged when disabled", func() {
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
			mockResponse := new(dns.Msg)
			mockResponse.SetReply(request)
			mockResponse.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.1"),
				},
			}
			m.On("Resolve", mock.Anything).Return(&model.Response{Res: mockResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.Res).Should(Equal(mockResponse))
			m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
		})
	})

	Describe("Configuration", func() {
		When("no prefixes configured", func() {
			BeforeEach(func() {
				sutConfig.Prefixes = []netip.Prefix{}
			})

			It("should use default well-known prefix", func() {
				Expect(sut.prefixes).Should(HaveLen(1))
				Expect(sut.prefixes[0].String()).Should(Equal("64:ff9b::/96"))
			})
		})

		When("multiple prefixes configured", func() {
			BeforeEach(func() {
				sutConfig.Prefixes = []netip.Prefix{
					netip.MustParsePrefix("64:ff9b::/96"),
					netip.MustParsePrefix("2001:db8:64::/96"),
				}
			})

			It("should use all configured prefixes", func() {
				Expect(sut.prefixes).Should(HaveLen(2))
			})
		})

		When("exclusion set", func() {
			It("should include required hard-coded ranges", func() {
				// Check for IPv4-mapped addresses
				hasIPv4Mapped := false
				for _, prefix := range sut.exclusionSet {
					if prefix.String() == "::ffff:0.0.0.0/96" {
						hasIPv4Mapped = true

						break
					}
				}
				Expect(hasIPv4Mapped).Should(BeTrue())
			})

			It("should include configured DNS64 prefixes", func() {
				// Configured prefix should be in exclusion set
				hasConfiguredPrefix := false
				for _, prefix := range sut.exclusionSet {
					if prefix.String() == "64:ff9b::/96" {
						hasConfiguredPrefix = true

						break
					}
				}
				Expect(hasConfiguredPrefix).Should(BeTrue())
			})
		})
	})

	Describe("Non-AAAA queries", func() {
		It("should pass through A queries unchanged", func() {
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
			mockResponse := new(dns.Msg)
			mockResponse.SetReply(request)
			m.On("Resolve", mock.Anything).Return(&model.Response{Res: mockResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.Res).Should(Equal(mockResponse))
			m.AssertCalled(GinkgoT(), "Resolve", mock.Anything)
		})

		It("should pass through MX queries unchanged", func() {
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeMX))
			mockResponse := new(dns.Msg)
			mockResponse.SetReply(request)
			m.On("Resolve", mock.Anything).Return(&model.Response{Res: mockResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.Res).Should(Equal(mockResponse))
		})
	})

	Describe("AAAA queries with existing valid records", func() {
		It("should return existing AAAA records without synthesis", func() {
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

			// Mock response with existing AAAA record
			mockResponse := new(dns.Msg)
			mockResponse.SetReply(request)
			mockResponse.Answer = []dns.RR{
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: net.ParseIP("2001:db8::1"),
				},
			}
			m.On("Resolve", mock.Anything).Return(&model.Response{Res: mockResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(HaveLen(1))
			Expect(resp.Res.Answer[0].(*dns.AAAA).AAAA.String()).Should(Equal("2001:db8::1"))
			// Should only call next resolver once (for AAAA query)
			m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
		})
	})

	Describe("Basic DNS64 synthesis", func() {
		It("should synthesize AAAA from A record when no AAAA exists", func() {
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

			// AAAA response: empty
			aaaaResponse := new(dns.Msg)
			aaaaResponse.SetReply(request)

			// A response: has A record
			aRequest := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
			aResponse := new(dns.Msg)
			aResponse.SetReply(aRequest)
			aResponse.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.1"),
				},
			}

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeAAAA
			})).Return(&model.Response{Res: aaaaResponse}, nil)

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeA
			})).Return(&model.Response{Res: aResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(HaveLen(1))
			aaaa := resp.Res.Answer[0].(*dns.AAAA)
			Expect(aaaa.AAAA.String()).Should(Equal("64:ff9b::c000:201")) // 192.0.2.1 embedded
			Expect(aaaa.Hdr.Ttl).Should(Equal(uint32(300)))
			Expect(resp.RType).Should(Equal(model.ResponseTypeSYNTHESIZED))
			Expect(resp.Reason).Should(Equal("DNS64"))
		})

		It("should synthesize multiple AAAA records from multiple A records", func() {
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

			aaaaResponse := new(dns.Msg)
			aaaaResponse.SetReply(request)

			aRequest := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
			aResponse := new(dns.Msg)
			aResponse.SetReply(aRequest)
			aResponse.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.1"),
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.2"),
				},
			}

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeAAAA
			})).Return(&model.Response{Res: aaaaResponse}, nil)

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeA
			})).Return(&model.Response{Res: aResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(HaveLen(2))
			Expect(resp.Res.Answer[0].(*dns.AAAA).AAAA.String()).Should(Equal("64:ff9b::c000:201"))
			Expect(resp.Res.Answer[1].(*dns.AAAA).AAAA.String()).Should(Equal("64:ff9b::c000:202"))
		})
	})

	Describe("Multiple prefixes", func() {
		BeforeEach(func() {
			sutConfig.Prefixes = []netip.Prefix{
				netip.MustParsePrefix("64:ff9b::/96"),
				netip.MustParsePrefix("2001:db8:64::/96"),
			}
		})

		It("should generate one AAAA per prefix per A record", func() {
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

			aaaaResponse := new(dns.Msg)
			aaaaResponse.SetReply(request)

			aRequest := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
			aResponse := new(dns.Msg)
			aResponse.SetReply(aRequest)
			aResponse.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.1"),
				},
			}

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeAAAA
			})).Return(&model.Response{Res: aaaaResponse}, nil)

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeA
			})).Return(&model.Response{Res: aResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(HaveLen(2)) // 1 A record × 2 prefixes = 2 AAAA records
			Expect(resp.Res.Answer[0].(*dns.AAAA).AAAA.String()).Should(Equal("64:ff9b::c000:201"))
			Expect(resp.Res.Answer[1].(*dns.AAAA).AAAA.String()).Should(Equal("2001:db8:64::c000:201"))
		})
	})

	Describe("IPv4-to-IPv6 embedding", func() {
		testCases := []struct {
			prefix   string
			ipv4     string
			expected string
		}{
			{prefix: "64:ff9b::/96", ipv4: "192.0.2.1", expected: "64:ff9b::c000:201"},
			{prefix: "64:ff9b::/96", ipv4: "192.0.2.255", expected: "64:ff9b::c000:2ff"},
			{prefix: "2001:db8::/32", ipv4: "192.0.2.1", expected: "2001:db8:c000:201::"},
			{prefix: "2001:db8::/40", ipv4: "192.0.2.1", expected: "2001:db8:c0:2:1::"},
			{prefix: "2001:db8::/48", ipv4: "192.0.2.1", expected: "2001:db8:0:c000:2:100::"},
			{prefix: "2001:db8::/56", ipv4: "192.0.2.1", expected: "2001:db8:0:c0:0:201::"},
			{prefix: "2001:db8::/64", ipv4: "192.0.2.1", expected: "2001:db8::c0:2:100:0"},
		}

		for _, tc := range testCases {
			It("should correctly embed "+tc.ipv4+" in "+tc.prefix, func() {
				prefix := netip.MustParsePrefix(tc.prefix)
				ipv4 := net.ParseIP(tc.ipv4)
				result := embedIPv4InIPv6(ipv4, prefix)

				Expect(result).ShouldNot(BeNil())
				Expect(result.String()).Should(Equal(tc.expected))
			})
		}

		It("should return nil for invalid IPv4", func() {
			prefix := netip.MustParsePrefix("64:ff9b::/96")
			invalidIPv4 := net.ParseIP("2001:db8::1") // IPv6, not IPv4
			result := embedIPv4InIPv6(invalidIPv4, prefix)

			Expect(result).Should(BeNil())
		})
	})

	Describe("Exclusion set", func() {
		When("AAAA record is IPv4-mapped", func() {
			It("should synthesize when all AAAA records are IPv4-mapped", func() {
				request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

				// AAAA response with IPv4-mapped address
				aaaaResponse := new(dns.Msg)
				aaaaResponse.SetReply(request)
				aaaaResponse.Answer = []dns.RR{
					&dns.AAAA{
						Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
						AAAA: net.ParseIP("::ffff:192.0.2.1"), // IPv4-mapped
					},
				}

				aRequest := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
				aResponse := new(dns.Msg)
				aResponse.SetReply(aRequest)
				aResponse.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.ParseIP("192.0.2.1"),
					},
				}

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeAAAA
				})).Return(&model.Response{Res: aaaaResponse}, nil)

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeA
				})).Return(&model.Response{Res: aResponse}, nil)

				resp, err := sut.Resolve(ctx, &model.Request{Req: request})

				Expect(err).Should(Succeed())
				Expect(resp.Res.Answer).Should(HaveLen(1))
				Expect(resp.Res.Answer[0].(*dns.AAAA).AAAA.String()).Should(Equal("64:ff9b::c000:201"))
			})
		})

		When("AAAA record matches configured DNS64 prefix", func() {
			It("should synthesize to prevent double-synthesis loop", func() {
				request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

				// AAAA response with address in DNS64 prefix range
				aaaaResponse := new(dns.Msg)
				aaaaResponse.SetReply(request)
				aaaaResponse.Answer = []dns.RR{
					&dns.AAAA{
						Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
						AAAA: net.ParseIP("64:ff9b::c000:201"), // Already synthesized
					},
				}

				aRequest := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
				aResponse := new(dns.Msg)
				aResponse.SetReply(aRequest)
				aResponse.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.ParseIP("192.0.2.1"),
					},
				}

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeAAAA
				})).Return(&model.Response{Res: aaaaResponse}, nil)

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeA
				})).Return(&model.Response{Res: aResponse}, nil)

				resp, err := sut.Resolve(ctx, &model.Request{Req: request})

				Expect(err).Should(Succeed())
				// Should synthesize fresh
				Expect(resp.RType).Should(Equal(model.ResponseTypeSYNTHESIZED))
			})
		})

		When("AAAA record is loopback", func() {
			It("should synthesize when AAAA is loopback", func() {
				request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

				aaaaResponse := new(dns.Msg)
				aaaaResponse.SetReply(request)
				aaaaResponse.Answer = []dns.RR{
					&dns.AAAA{
						Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
						AAAA: net.ParseIP("::1"), // Loopback
					},
				}

				aRequest := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
				aResponse := new(dns.Msg)
				aResponse.SetReply(aRequest)
				aResponse.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.ParseIP("192.0.2.1"),
					},
				}

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeAAAA
				})).Return(&model.Response{Res: aaaaResponse}, nil)

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeA
				})).Return(&model.Response{Res: aResponse}, nil)

				resp, err := sut.Resolve(ctx, &model.Request{Req: request})

				Expect(err).Should(Succeed())
				Expect(resp.RType).Should(Equal(model.ResponseTypeSYNTHESIZED))
			})
		})

		When("mixed excluded and non-excluded AAAA records", func() {
			It("should NOT synthesize when mix exists", func() {
				request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

				aaaaResponse := new(dns.Msg)
				aaaaResponse.SetReply(request)
				aaaaResponse.Answer = []dns.RR{
					&dns.AAAA{
						Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
						AAAA: net.ParseIP("2001:db8::1"), // Valid
					},
					&dns.AAAA{
						Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
						AAAA: net.ParseIP("::1"), // Excluded (loopback)
					},
				}

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeAAAA
				})).Return(&model.Response{Res: aaaaResponse}, nil)

				resp, err := sut.Resolve(ctx, &model.Request{Req: request})

				Expect(err).Should(Succeed())
				Expect(resp.Res.Answer).Should(HaveLen(2)) // Return both as-is
				// Should NOT call A query
				m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
			})
		})
	})

	Describe("RCODE handling", func() {
		It("should return NXDOMAIN without synthesis", func() {
			request := util.NewMsgWithQuestion("notexist.com.", dns.Type(dns.TypeAAAA))

			aaaaResponse := new(dns.Msg)
			aaaaResponse.SetReply(request)

			aRequest := util.NewMsgWithQuestion("notexist.com.", dns.Type(dns.TypeA))
			aResponse := new(dns.Msg)
			aResponse.SetReply(aRequest)
			aResponse.Rcode = dns.RcodeNameError // NXDOMAIN

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeAAAA
			})).Return(&model.Response{Res: aaaaResponse}, nil)

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeA
			})).Return(&model.Response{Res: aResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
			Expect(resp.Reason).Should(Equal("NXDOMAIN"))
		})

		It("should treat SERVFAIL as empty response (alternative behavior)", func() {
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

			aaaaResponse := new(dns.Msg)
			aaaaResponse.SetReply(request)

			aRequest := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
			aResponse := new(dns.Msg)
			aResponse.SetReply(aRequest)
			aResponse.Rcode = dns.RcodeServerFailure // SERVFAIL

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeAAAA
			})).Return(&model.Response{Res: aaaaResponse}, nil)

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeA
			})).Return(&model.Response{Res: aResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			// Should return original empty AAAA response
			Expect(resp.Res.Answer).Should(BeEmpty())
		})
	})

	Describe("TTL handling", func() {
		When("multiple A records with different TTLs", func() {
			It("should use minimum TTL for all AAAA records", func() {
				request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

				aaaaResponse := new(dns.Msg)
				aaaaResponse.SetReply(request)

				aRequest := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
				aResponse := new(dns.Msg)
				aResponse.SetReply(aRequest)
				aResponse.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.ParseIP("192.0.2.1"),
					},
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
						A:   net.ParseIP("192.0.2.2"),
					},
				}

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeAAAA
				})).Return(&model.Response{Res: aaaaResponse}, nil)

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeA
				})).Return(&model.Response{Res: aResponse}, nil)

				resp, err := sut.Resolve(ctx, &model.Request{Req: request})

				Expect(err).Should(Succeed())
				Expect(resp.Res.Answer).Should(HaveLen(2))
				Expect(resp.Res.Answer[0].(*dns.AAAA).Hdr.Ttl).Should(Equal(uint32(300))) // min(300, 600)
				Expect(resp.Res.Answer[1].(*dns.AAAA).Hdr.Ttl).Should(Equal(uint32(300))) // min(300, 600)
			})
		})

		When("CNAME chain with different TTLs", func() {
			It("should use minimum TTL across CNAME and A records (cache coherency)", func() {
				request := util.NewMsgWithQuestion("app.example.com.", dns.Type(dns.TypeAAAA))

				aaaaResponse := new(dns.Msg)
				aaaaResponse.SetReply(request)

				aRequest := util.NewMsgWithQuestion("app.example.com.", dns.Type(dns.TypeA))
				aResponse := new(dns.Msg)
				aResponse.SetReply(aRequest)
				aResponse.Answer = []dns.RR{
					&dns.CNAME{
						Hdr:    dns.RR_Header{Name: "app.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
						Target: "cdn.provider.net.",
					},
					&dns.A{
						Hdr: dns.RR_Header{Name: "cdn.provider.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
						A:   net.ParseIP("192.0.2.1"),
					},
				}

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeAAAA
				})).Return(&model.Response{Res: aaaaResponse}, nil)

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeA
				})).Return(&model.Response{Res: aResponse}, nil)

				resp, err := sut.Resolve(ctx, &model.Request{Req: request})

				Expect(err).Should(Succeed())
				Expect(resp.Res.Answer).Should(HaveLen(2)) // CNAME + AAAA
				// First record is CNAME
				Expect(resp.Res.Answer[0].Header().Rrtype).Should(Equal(dns.TypeCNAME))
				// Second record is synthesized AAAA with minimum TTL
				aaaa := resp.Res.Answer[1].(*dns.AAAA)
				Expect(aaaa.Hdr.Ttl).Should(Equal(uint32(60))) // min(60, 3600) = 60 (CNAME TTL)
				Expect(aaaa.Hdr.Name).Should(Equal("cdn.provider.net."))
			})
		})

		When("DNAME chain with different TTLs", func() {
			It("should use minimum TTL across DNAME, CNAME, and A records", func() {
				request := util.NewMsgWithQuestion("sub.example.com.", dns.Type(dns.TypeAAAA))

				aaaaResponse := new(dns.Msg)
				aaaaResponse.SetReply(request)

				aRequest := util.NewMsgWithQuestion("sub.example.com.", dns.Type(dns.TypeA))
				aResponse := new(dns.Msg)
				aResponse.SetReply(aRequest)
				aResponse.Answer = []dns.RR{
					&dns.DNAME{
						Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 300},
						Target: "cdn.example.net.",
					},
					&dns.CNAME{
						Hdr:    dns.RR_Header{Name: "sub.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
						Target: "sub.cdn.example.net.",
					},
					&dns.A{
						Hdr: dns.RR_Header{Name: "sub.cdn.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1800},
						A:   net.ParseIP("192.0.2.50"),
					},
				}

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeAAAA
				})).Return(&model.Response{Res: aaaaResponse}, nil)

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeA
				})).Return(&model.Response{Res: aResponse}, nil)

				resp, err := sut.Resolve(ctx, &model.Request{Req: request})

				Expect(err).Should(Succeed())
				Expect(resp.Res.Answer).Should(HaveLen(3)) // DNAME + CNAME + AAAA
				aaaa := resp.Res.Answer[2].(*dns.AAAA)
				Expect(aaaa.Hdr.Ttl).Should(Equal(uint32(300))) // min(300, 300, 1800) = 300
			})
		})
	})

	Describe("DNSSEC flag handling", func() {
		It("should copy DO bit from AAAA query to A query", func() {
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))
			request.SetEdns0(4096, true) // Set DO=1

			aaaaResponse := new(dns.Msg)
			aaaaResponse.SetReply(request)

			var capturedAReq *dns.Msg
			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				if req.Req.Question[0].Qtype == dns.TypeA {
					capturedAReq = req.Req

					return true
				}

				return req.Req.Question[0].Qtype == dns.TypeAAAA
			})).Return(&model.Response{Res: aaaaResponse}, nil).Twice()

			_, err := sut.Resolve(ctx, &model.Request{Req: request})
			Expect(err).Should(Succeed())

			Expect(capturedAReq).ShouldNot(BeNil())
			opt := capturedAReq.IsEdns0()
			Expect(opt).ShouldNot(BeNil())
			Expect(opt.Do()).Should(BeTrue()) // DO bit copied
		})

		It("should clear AD bit in synthesized response", func() {
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

			aaaaResponse := new(dns.Msg)
			aaaaResponse.SetReply(request)

			aRequest := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
			aResponse := new(dns.Msg)
			aResponse.SetReply(aRequest)
			aResponse.AuthenticatedData = true // AD=1 from upstream
			aResponse.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.1"),
				},
			}

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeAAAA
			})).Return(&model.Response{Res: aaaaResponse}, nil)

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeA
			})).Return(&model.Response{Res: aResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.Res.AuthenticatedData).Should(BeFalse()) // AD bit cleared (non-validating mode)
		})

		It("should copy AA and RA bits from A response", func() {
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

			aaaaResponse := new(dns.Msg)
			aaaaResponse.SetReply(request)

			aRequest := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
			aResponse := new(dns.Msg)
			aResponse.SetReply(aRequest)
			aResponse.Authoritative = true
			aResponse.RecursionAvailable = true
			aResponse.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.1"),
				},
			}

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeAAAA
			})).Return(&model.Response{Res: aaaaResponse}, nil)

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeA
			})).Return(&model.Response{Res: aResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.Res.Authoritative).Should(BeTrue())
			Expect(resp.Res.RecursionAvailable).Should(BeTrue())
		})
	})

	Describe("Empty AAAA response vs NXDOMAIN", func() {
		It("should synthesize for NOERROR with zero AAAA records", func() {
			request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

			// AAAA response: NOERROR with empty answer
			aaaaResponse := new(dns.Msg)
			aaaaResponse.SetReply(request)
			aaaaResponse.Rcode = dns.RcodeSuccess

			aRequest := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA))
			aResponse := new(dns.Msg)
			aResponse.SetReply(aRequest)
			aResponse.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.1"),
				},
			}

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeAAAA
			})).Return(&model.Response{Res: aaaaResponse}, nil)

			m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
				return req.Req.Question[0].Qtype == dns.TypeA
			})).Return(&model.Response{Res: aResponse}, nil)

			resp, err := sut.Resolve(ctx, &model.Request{Req: request})

			Expect(err).Should(Succeed())
			Expect(resp.RType).Should(Equal(model.ResponseTypeSYNTHESIZED))
		})
	})

	Describe("Phase 2: Configurable exclusion set", func() {
		When("custom exclusion set is configured", func() {
			BeforeEach(func() {
				sutConfig.ExclusionSet = []netip.Prefix{
					netip.MustParsePrefix("2001:db8::/32"), // Custom exclusion
				}
			})

			It("should use custom exclusion set instead of defaults", func() {
				// Should have exactly one exclusion range (our custom one)
				Expect(sut.exclusionSet).Should(HaveLen(1))
				Expect(sut.exclusionSet[0].String()).Should(Equal("2001:db8::/32"))
			})

			It("should exclude addresses matching custom exclusion set", func() {
				request := util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeAAAA))

				// Mock AAAA response with address in custom exclusion set
				aaaaResponse := new(dns.Msg)
				aaaaResponse.SetReply(request)
				aaaaResponse.Answer = []dns.RR{
					&dns.AAAA{
						Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
						AAAA: net.ParseIP("2001:db8::1"), // Matches our custom exclusion
					},
				}

				// Mock A response for synthesis
				aResponse := new(dns.Msg)
				aResponse.SetReply(request)
				aResponse.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.ParseIP("192.0.2.1"),
					},
				}

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeAAAA
				})).Return(&model.Response{Res: aaaaResponse}, nil)

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeA
				})).Return(&model.Response{Res: aResponse}, nil)

				resp, err := sut.Resolve(ctx, &model.Request{Req: request})

				Expect(err).Should(Succeed())
				Expect(resp.RType).Should(Equal(model.ResponseTypeSYNTHESIZED))
				Expect(resp.Res.Answer).Should(HaveLen(1))
				Expect(resp.Res.Answer[0].(*dns.AAAA).AAAA.String()).Should(Equal("64:ff9b::c000:201"))
			})
		})

		When("empty exclusion set is configured", func() {
			BeforeEach(func() {
				sutConfig.ExclusionSet = []netip.Prefix{
					netip.MustParsePrefix("::ffff:0:0/96"),
					netip.MustParsePrefix("::1/128"),
					netip.MustParsePrefix("fe80::/10"),
				}
			})

			It("should use configured exclusion set", func() {
				Expect(sut.exclusionSet).Should(HaveLen(3))
			})
		})
	})

	Describe("Phase 2: Integration with other resolvers", func() {
		When("integrated with CustomDNSResolver", func() {
			It("should synthesize AAAA from custom A records", func() {
				// This simulates CustomDNSResolver returning a custom A record
				// and DNS64 synthesizing AAAA from it
				request := util.NewMsgWithQuestion("custom.local.", dns.Type(dns.TypeAAAA))

				// Mock: CustomDNS returns no AAAA
				emptyAAAAResponse := new(dns.Msg)
				emptyAAAAResponse.SetReply(request)

				// Mock: CustomDNS returns custom A record
				customAResponse := new(dns.Msg)
				customAResponse.SetReply(request)
				customAResponse.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "custom.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
						A:   net.ParseIP("10.0.0.1"), // Custom local IP
					},
				}

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeAAAA
				})).Return(&model.Response{Res: emptyAAAAResponse}, nil)

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeA
				})).Return(&model.Response{Res: customAResponse}, nil)

				resp, err := sut.Resolve(ctx, &model.Request{Req: request})

				Expect(err).Should(Succeed())
				Expect(resp.RType).Should(Equal(model.ResponseTypeSYNTHESIZED))
				Expect(resp.Res.Answer).Should(HaveLen(1))

				// Verify synthesized AAAA contains embedded 10.0.0.1
				aaaa := resp.Res.Answer[0].(*dns.AAAA)
				Expect(aaaa.AAAA.String()).Should(Equal("64:ff9b::a00:1"))
			})
		})

		When("integrated with BlockingResolver", func() {
			It("should not synthesize for blocked domains", func() {
				// This simulates BlockingResolver returning NXDOMAIN for blocked domain
				// DNS64 queries for A records and gets NXDOMAIN, then returns NXDOMAIN
				request := util.NewMsgWithQuestion("blocked.example.com.", dns.Type(dns.TypeAAAA))

				// Mock: BlockingResolver returns empty AAAA response (no AAAA records)
				emptyAAAAResponse := new(dns.Msg)
				emptyAAAAResponse.SetReply(request)

				// Mock: BlockingResolver returns NXDOMAIN for A query
				blockedAResponse := new(dns.Msg)
				blockedAResponse.SetReply(request)
				blockedAResponse.Rcode = dns.RcodeNameError

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeAAAA
				})).Return(&model.Response{Res: emptyAAAAResponse}, nil)

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeA
				})).Return(&model.Response{Res: blockedAResponse}, nil)

				resp, err := sut.Resolve(ctx, &model.Request{Req: request})

				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
				Expect(resp.Reason).Should(Equal("NXDOMAIN"))
			})
		})

		When("integrated with CachingResolver", func() {
			It("should cache synthesized AAAA records", func() {
				// This test verifies that synthesized AAAA records can be cached
				// The actual caching is done by CachingResolver, but this tests that
				// synthesized responses have proper TTL for caching

				request := util.NewMsgWithQuestion("cacheable.example.com.", dns.Type(dns.TypeAAAA))

				emptyAAAAResponse := new(dns.Msg)
				emptyAAAAResponse.SetReply(request)

				aResponse := new(dns.Msg)
				aResponse.SetReply(request)
				aResponse.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "cacheable.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1800},
						A:   net.ParseIP("192.0.2.100"),
					},
				}

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeAAAA
				})).Return(&model.Response{Res: emptyAAAAResponse}, nil)

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeA
				})).Return(&model.Response{Res: aResponse}, nil)

				resp, err := sut.Resolve(ctx, &model.Request{Req: request})

				Expect(err).Should(Succeed())
				Expect(resp.RType).Should(Equal(model.ResponseTypeSYNTHESIZED))

				// Verify synthesized AAAA has proper TTL (should match A record TTL)
				aaaa := resp.Res.Answer[0].(*dns.AAAA)
				Expect(aaaa.Hdr.Ttl).Should(Equal(uint32(1800)))

				// Verify response is cacheable (has positive TTL)
				Expect(aaaa.Hdr.Ttl).Should(BeNumerically(">", 0))
			})
		})

		When("integrated with ConditionalUpstreamResolver", func() {
			It("should synthesize from conditional upstream A records", func() {
				// This simulates DNS64 synthesizing from A records retrieved via
				// conditional upstream (e.g., corporate DNS for *.corp domain)
				request := util.NewMsgWithQuestion("app.corp.", dns.Type(dns.TypeAAAA))

				emptyAAAAResponse := new(dns.Msg)
				emptyAAAAResponse.SetReply(request)

				// Mock: Conditional upstream returns A record for corporate domain
				corpAResponse := new(dns.Msg)
				corpAResponse.SetReply(request)
				corpAResponse.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "app.corp.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
						A:   net.ParseIP("172.16.0.10"), // Private corporate IP
					},
				}

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeAAAA
				})).Return(&model.Response{Res: emptyAAAAResponse}, nil)

				m.On("Resolve", mock.MatchedBy(func(req *model.Request) bool {
					return req.Req.Question[0].Qtype == dns.TypeA
				})).Return(&model.Response{Res: corpAResponse}, nil)

				resp, err := sut.Resolve(ctx, &model.Request{Req: request})

				Expect(err).Should(Succeed())
				Expect(resp.RType).Should(Equal(model.ResponseTypeSYNTHESIZED))

				// Verify synthesized AAAA from corporate private IP
				aaaa := resp.Res.Answer[0].(*dns.AAAA)
				Expect(aaaa.AAAA.String()).Should(Equal("64:ff9b::ac10:a"))
			})
		})
	})
})

var _ = Describe("embedIPv4InIPv6", func() {
	It("should handle all prefix lengths correctly", func() {
		ipv4 := net.ParseIP("192.0.2.1")

		// Test all valid prefix lengths
		testCases := []struct {
			prefixLen int
			prefix    string
		}{
			{96, "64:ff9b::/96"},
			{64, "2001:db8::/64"},
			{56, "2001:db8::/56"},
			{48, "2001:db8::/48"},
			{40, "2001:db8::/40"},
			{32, "2001:db8::/32"},
		}

		for _, tc := range testCases {
			prefix := netip.MustParsePrefix(tc.prefix)
			result := embedIPv4InIPv6(ipv4, prefix)
			Expect(result).ShouldNot(BeNil(), "Embedding should succeed for prefix length /%d", tc.prefixLen)

			// Verify result is IPv6
			Expect(result.To4()).Should(BeNil())
			Expect(result.To16()).ShouldNot(BeNil())

			// Verify byte 8 is zero for non-/96 prefixes (RFC 6052 requirement)
			if tc.prefixLen != 96 {
				Expect(result.To16()[8]).Should(Equal(byte(0)), "Byte 8 (reserved/u bit) must be 0 for /%d prefix", tc.prefixLen)
			}
		}
	})
})
