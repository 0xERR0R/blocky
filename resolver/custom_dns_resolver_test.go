package resolver

import (
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
		TTL = uint32(time.Now().Second())

		sut ChainedResolver
		m   *mockResolver
		cfg config.CustomDNSConfig
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		cfg = config.CustomDNSConfig{
			Mapping: config.CustomDNSMapping{HostIPs: map[string][]net.IP{
				"custom.domain": {net.ParseIP("192.168.143.123")},
				"ip6.domain":    {net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
				"multiple.ips": {
					net.ParseIP("192.168.143.123"),
					net.ParseIP("192.168.143.125"),
					net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
				},
			}},
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
		When("Ip 4 mapping is defined for custom domain and", func() {
			Context("filterUnmappedTypes is true", func() {
				BeforeEach(func() { cfg.FilterUnmappedTypes = true })
				It("defined ip4 query should be resolved", func() {
					Expect(sut.Resolve(newRequest("custom.domain.", A))).
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
					Expect(sut.Resolve(newRequest("custom.domain.", TXT))).
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
					Expect(sut.Resolve(newRequest("custom.domain.", AAAA))).
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
					Expect(sut.Resolve(newRequest("custom.domain.", A))).
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
					Expect(sut.Resolve(newRequest("custom.domain.", TXT))).
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
					Expect(sut.Resolve(newRequest("custom.domain.", AAAA))).
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
				Expect(sut.Resolve(newRequest("ip6.domain.", AAAA))).
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
					Expect(sut.Resolve(newRequest("multiple.ips.", AAAA))).
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
					Expect(sut.Resolve(newRequest("multiple.ips.", A))).
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
		When("Reverse DNS request is received", func() {
			It("should resolve the defined domain name", func() {
				By("ipv4", func() {
					Expect(sut.Resolve(newRequest("123.143.168.192.in-addr.arpa.", PTR))).
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
					Expect(sut.Resolve(newRequest("4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa.",
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
				Expect(sut.Resolve(newRequest("ABC.CUSTOM.DOMAIN.", A))).
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
				Expect(sut.Resolve(newRequest("example.com.", A))).
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
