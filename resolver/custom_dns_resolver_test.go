package resolver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("CustomDNSResolver", func() {
	var (
		TTL     = uint32(time.Now().Second())
		zoneTTL = uint32(time.Now().Second() * 2)

		sut *CustomDNSResolver
		m   *mockResolver
		cfg config.CustomDNS

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

		zoneHdr := dns.RR_Header{Ttl: zoneTTL}

		cfg = config.CustomDNS{
			Mapping: config.CustomDNSMapping{
				"custom.domain": {&dns.A{A: net.ParseIP("192.168.143.123")}},
				"ip6.domain":    {&dns.AAAA{AAAA: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")}},
				"multiple.ips": {
					&dns.A{A: net.ParseIP("192.168.143.123")},
					&dns.A{A: net.ParseIP("192.168.143.125")},
					&dns.AAAA{AAAA: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
				},
			},
			Zone: config.ZoneFileDNS{
				RRs: config.CustomDNSMapping{
					"example.zone.":    {&dns.A{A: net.ParseIP("1.2.3.4"), Hdr: zoneHdr}},
					"cname.domain.":    {&dns.CNAME{Target: "custom.domain", Hdr: zoneHdr}},
					"cname.ip6.":       {&dns.CNAME{Target: "ip6.domain", Hdr: zoneHdr}},
					"cname.example.":   {&dns.CNAME{Target: "example.com", Hdr: zoneHdr}},
					"cname.recursive.": {&dns.CNAME{Target: "cname.recursive", Hdr: zoneHdr}},
					"mx.domain.":       {&dns.MX{Mx: "mx.domain", Hdr: zoneHdr}},
				},
			},
			CustomTTL:           config.Duration(time.Duration(TTL) * time.Second),
			FilterUnmappedTypes: true,
		}
	})

	JustBeforeEach(func() {
		sut = NewCustomDNSResolver(cfg)
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

	Describe("Resolving custom name via CustomDNSResolver", func() {
		When("The parent context has an error ", func() {
			It("should return the error", func() {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel()

				_, err := sut.Resolve(cancelledCtx, newRequest("custom.domain.", A))

				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("context canceled"))
			})
		})
		When("Creating the IP response returns an error ", func() {
			It("should return the error", func() {
				createAnswerMock := func(_ dns.Question, _ net.IP, _ uint32) (dns.RR, error) {
					return nil, fmt.Errorf("create answer error")
				}

				sut.CreateAnswerFromQuestion(createAnswerMock)

				_, err := sut.Resolve(ctx, newRequest("custom.domain.", A))

				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("create answer error"))
			})
		})
		When("The forward request returns an error ", func() {
			It("should return the error if the error occurs when checking ipv4 forward addresses", func() {
				err := fmt.Errorf("forward error")
				m = &mockResolver{}

				m.On("Resolve", mock.Anything).Return(nil, err)

				sut.Next(m)
				_, err = sut.Resolve(ctx, newRequest("cname.example.", A))

				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("forward error"))
			})
			It("should return the error if the error occurs when checking ipv6 forward addresses", func() {
				err := fmt.Errorf("forward error")
				m = &mockResolver{}

				m.On("Resolve", mock.Anything).Return(nil, err)

				sut.Next(m)
				_, err = sut.Resolve(ctx, newRequest("cname.example.", AAAA))

				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("forward error"))
			})
		})
		When("Ip 4 mapping is defined for custom domain and", func() {
			Context("filterUnmappedTypes is true", func() {
				BeforeEach(func() { cfg.FilterUnmappedTypes = true })
				It("defined ip4 query should be resolved from zone mappings and should use the TTL defined in the zone", func() {
					Expect(sut.Resolve(ctx, newRequest("example.zone.", A))).
						Should(
							SatisfyAll(
								BeDNSRecord("example.zone.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", zoneTTL)),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
				It("defined ip4 query should be resolved", func() {
					Expect(sut.Resolve(ctx, newRequest("custom.domain.", A))).
						Should(
							SatisfyAll(
								BeDNSRecord("custom.domain.", A, "192.168.143.123"),
								HaveTTL(BeNumerically("==", TTL)),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
				It("TXT query for defined mapping should return NOERROR and empty result", func() {
					Expect(sut.Resolve(ctx, newRequest("custom.domain.", TXT))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
				It("ip6 query should return NOERROR and empty result", func() {
					Expect(sut.Resolve(ctx, newRequest("custom.domain.", AAAA))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
			})

			Context("filterUnmappedTypes is false", func() {
				BeforeEach(func() { cfg.FilterUnmappedTypes = false })
				It("defined ip4 query should be resolved", func() {
					Expect(sut.Resolve(ctx, newRequest("custom.domain.", A))).
						Should(
							SatisfyAll(
								BeDNSRecord("custom.domain.", A, "192.168.143.123"),
								HaveTTL(BeNumerically("==", TTL)),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
				It("TXT query for defined mapping should be delegated to next resolver", func() {
					Expect(sut.Resolve(ctx, newRequest("custom.domain.", TXT))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// delegate was executed
					m.AssertExpectations(GinkgoT())
				})
				It("ip6 query should return NOERROR and empty result", func() {
					Expect(sut.Resolve(ctx, newRequest("custom.domain.", AAAA))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// delegate was executed
					m.AssertExpectations(GinkgoT())
				})
			})
		})
		When("Ip 6 mapping is defined for custom domain ", func() {
			It("ip6 query should be resolved", func() {
				Expect(sut.Resolve(ctx, newRequest("ip6.domain.", AAAA))).
					Should(
						SatisfyAll(
							BeDNSRecord("ip6.domain.", AAAA, "2001:db8:85a3::8a2e:370:7334"),
							HaveTTL(BeNumerically("==", TTL)),
							HaveResponseType(ResponseTypeCUSTOMDNS),
							HaveReason("CUSTOM DNS"),
							HaveReturnCode(dns.RcodeSuccess),
						))
				// will not delegate to next resolver
				m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
			})
		})
		When("Multiple IPs are defined for custom domain ", func() {
			It("all IPs for the current type should be returned", func() {
				By("IPv6 query", func() {
					Expect(sut.Resolve(ctx, newRequest("multiple.ips.", AAAA))).
						Should(
							SatisfyAll(
								BeDNSRecord("multiple.ips.", AAAA, "2001:db8:85a3::8a2e:370:7334"),
								HaveTTL(BeNumerically("==", TTL)),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})

				By("IPv4 query", func() {
					Expect(sut.Resolve(ctx, newRequest("multiple.ips.", A))).
						Should(
							SatisfyAll(
								WithTransform(ToAnswer, SatisfyAll(
									HaveLen(2),
									ContainElements(
										BeDNSRecord("multiple.ips.", A, "192.168.143.123"),
										BeDNSRecord("multiple.ips.", A, "192.168.143.125")),
								)),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
			})
		})
		When("A CNAME record is defined for custom domain ", func() {
			It("should not recurse if the request is strictly a CNAME request", func() {
				By("CNAME query", func() {
					Expect(sut.Resolve(ctx, newRequest("cname.domain", CNAME))).
						Should(
							SatisfyAll(
								WithTransform(ToAnswer, SatisfyAll(
									HaveLen(1),
									ContainElements(
										BeDNSRecord("cname.domain.", CNAME, "custom.domain.")),
								)),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
			})
			It("all CNAMES for the current type should be recursively resolved when relying on other Mappings", func() {
				By("A query", func() {
					Expect(sut.Resolve(ctx, newRequest("cname.domain", A))).
						Should(
							SatisfyAll(
								WithTransform(ToAnswer, SatisfyAll(
									HaveLen(2),
									ContainElements(
										BeDNSRecord("cname.domain.", CNAME, "custom.domain."),
										BeDNSRecord("custom.domain.", A, "192.168.143.123")),
								)),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
				By("AAAA query", func() {
					Expect(sut.Resolve(ctx, newRequest("cname.ip6", AAAA))).
						Should(
							SatisfyAll(
								WithTransform(ToAnswer, SatisfyAll(
									HaveLen(2),
									ContainElements(
										BeDNSRecord("cname.ip6.", CNAME, "ip6.domain."),
										BeDNSRecord("ip6.domain.", AAAA, "2001:db8:85a3::8a2e:370:7334")),
								)),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
			})
			It("should return an error when the CNAME is recursive", func() {
				By("CNAME query", func() {
					_, err := sut.Resolve(ctx, newRequest("cname.recursive", A))
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("CNAME loop detected:"))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
			})
			It("all CNAMES for the current type should be returned when relying on public DNS", func() {
				By("CNAME query", func() {
					Expect(sut.Resolve(ctx, newRequest("cname.example", A))).
						Should(
							SatisfyAll(
								WithTransform(ToAnswer, SatisfyAll(
									ContainElements(
										BeDNSRecord("cname.example.", CNAME, "example.com.")),
								)),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// will delegate to next resolver
					m.AssertCalled(GinkgoT(), "Resolve", mock.Anything)
				})
			})
		})
		When("An unsupported DNS query type is queried from the resolver but found in the config mapping ", func() {
			It("an error should be returned", func() {
				By("MX query", func() {
					_, err := sut.Resolve(ctx, newRequest("mx.domain", MX))
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("unsupported customDNS RR type *dns.MX"))
				})
			})
		})
		When("Reverse DNS request is received", func() {
			It("should resolve the defined domain name", func() {
				By("ipv4", func() {
					Expect(sut.Resolve(ctx, newRequest("123.143.168.192.in-addr.arpa.", PTR))).
						Should(
							SatisfyAll(
								WithTransform(ToAnswer, SatisfyAll(
									HaveLen(2),
									ContainElements(
										BeDNSRecord("123.143.168.192.in-addr.arpa.", PTR, "custom.domain."),
										BeDNSRecord("123.143.168.192.in-addr.arpa.", PTR, "multiple.ips.")),
								)),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})

				By("ipv6", func() {
					Expect(sut.Resolve(ctx, newRequest("4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa.",
						PTR))).
						Should(
							SatisfyAll(
								WithTransform(ToAnswer, SatisfyAll(
									HaveLen(2),
									ContainElements(
										BeDNSRecord("4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa.",
											PTR, "ip6.domain."),
										BeDNSRecord("4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa.",
											PTR, "multiple.ips.")),
								)),
								HaveResponseType(ResponseTypeCUSTOMDNS),
								HaveReason("CUSTOM DNS"),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
			})
		})
		When("Domain mapping is defined", func() {
			It("subdomain must also match", func() {
				Expect(sut.Resolve(ctx, newRequest("ABC.CUSTOM.DOMAIN.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("ABC.CUSTOM.DOMAIN.", A, "192.168.143.123"),
							HaveTTL(BeNumerically("==", TTL)),
							HaveResponseType(ResponseTypeCUSTOMDNS),
							HaveReason("CUSTOM DNS"),
							HaveReturnCode(dns.RcodeSuccess),
						))
				// will not delegate to next resolver
				m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
			})
		})
	})

	Describe("Delegating to next resolver", func() {
		When("no mapping for domain exist", func() {
			It("should delegate to next resolver", func() {
				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))

				// delegate was executed
				m.AssertExpectations(GinkgoT())
			})
		})
	})
})
