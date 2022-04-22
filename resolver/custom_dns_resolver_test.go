package resolver

import (
	"net"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("CustomDNSResolver", func() {
	var (
		sut  ChainedResolver
		m    *MockResolver
		err  error
		resp *Response
		cfg  config.CustomDNSConfig
	)

	TTL := uint32(time.Now().Second())

	BeforeEach(func() {
		cfg = config.CustomDNSConfig{
			Mapping: config.CustomDNSMapping{HostIPs: map[string][]net.IP{
				"custom.domain": {net.ParseIP("192.168.143.123")},
				"ip6.domain":    {net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
				"multiple.ips": {
					net.ParseIP("192.168.143.123"),
					net.ParseIP("192.168.143.125"),
					net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
			}},
			CustomTTL:           config.Duration(time.Duration(TTL) * time.Second),
			FilterUnmappedTypes: true,
		}

	})

	JustBeforeEach(func() {
		sut = NewCustomDNSResolver(cfg)
		m = &MockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("Resolving custom name via CustomDNSResolver", func() {
		When("Ip 4 mapping is defined for custom domain and", func() {
			Context("filterUnmappedTypes is true", func() {
				BeforeEach(func() { cfg.FilterUnmappedTypes = true })
				It("defined ip4 query should be resolved", func() {
					resp, err = sut.Resolve(newRequest("custom.domain.", dns.Type(dns.TypeA)))

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(BeDNSRecord("custom.domain.", dns.TypeA, TTL, "192.168.143.123"))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
				It("TXT query for defined mapping should return NOERROR and empty result", func() {
					resp, err = sut.Resolve(newRequest("custom.domain.", dns.Type(dns.TypeTXT)))

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(HaveLen(0))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
				It("ip6 query should return NOERROR and empty result", func() {
					resp, err = sut.Resolve(newRequest("custom.domain.", dns.Type(dns.TypeAAAA)))

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(HaveLen(0))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
			})

			Context("filterUnmappedTypes is false", func() {
				BeforeEach(func() { cfg.FilterUnmappedTypes = false })
				It("defined ip4 query should be resolved", func() {
					resp, err = sut.Resolve(newRequest("custom.domain.", dns.Type(dns.TypeA)))

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(BeDNSRecord("custom.domain.", dns.TypeA, TTL, "192.168.143.123"))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
				It("TXT query for defined mapping should be delegated to next resolver", func() {
					resp, err = sut.Resolve(newRequest("custom.domain.", dns.Type(dns.TypeTXT)))

					// delegate was executed
					m.AssertExpectations(GinkgoT())
				})
				It("ip6 query should return NOERROR and empty result", func() {
					resp, err = sut.Resolve(newRequest("custom.domain.", dns.Type(dns.TypeAAAA)))

					// delegate was executed
					m.AssertExpectations(GinkgoT())
				})
			})

		})
		When("Ip 6 mapping is defined for custom domain ", func() {
			It("ip6 query should be resolved", func() {
				resp, err = sut.Resolve(newRequest("ip6.domain.", dns.Type(dns.TypeAAAA)))

				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Res.Answer).Should(BeDNSRecord("ip6.domain.", dns.TypeAAAA, TTL, "2001:db8:85a3::8a2e:370:7334"))
				// will not delegate to next resolver
				m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
			})
		})
		When("Multiple IPs are defined for custom domain ", func() {
			It("all IPs for the current type should be returned", func() {
				By("IPv6 query", func() {
					resp, err = sut.Resolve(newRequest("multiple.ips.", dns.Type(dns.TypeAAAA)))

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(BeDNSRecord("multiple.ips.", dns.TypeAAAA, TTL, "2001:db8:85a3::8a2e:370:7334"))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})

				By("IPv4 query", func() {
					resp, err = sut.Resolve(newRequest("multiple.ips.", dns.Type(dns.TypeA)))

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(HaveLen(2))
					Expect(resp.Res.Answer).Should(ContainElements(
						BeDNSRecord("multiple.ips.", dns.TypeA, TTL, "192.168.143.123")),
						BeDNSRecord("multiple.ips.", dns.TypeA, TTL, "192.168.143.125"))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
			})
		})
		When("Reverse DNS request is received", func() {
			It("should resolve the defined domain name", func() {
				By("ipv4", func() {
					resp, err = sut.Resolve(newRequest("123.143.168.192.in-addr.arpa.", dns.Type(dns.TypePTR)))

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(HaveLen(2))
					Expect(resp.Res.Answer).Should(ContainElements(
						BeDNSRecord("123.143.168.192.in-addr.arpa.", dns.TypePTR, TTL, "custom.domain."),
						BeDNSRecord("123.143.168.192.in-addr.arpa.", dns.TypePTR, TTL, "multiple.ips.")))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})

				By("ipv6", func() {
					resp, err = sut.Resolve(newRequest("4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa.",
						dns.Type(dns.TypePTR)))
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(HaveLen(2))
					Expect(resp.Res.Answer).Should(ContainElements(
						BeDNSRecord("4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa.",
							dns.TypePTR, TTL, "ip6.domain.")),
						BeDNSRecord("4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa.",
							dns.TypePTR, TTL, "multiple.ips."))
					// will not delegate to next resolver
					m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
				})
			})
		})
		When("Domain mapping is defined", func() {
			It("subdomain must also match", func() {
				resp, err = sut.Resolve(newRequest("ABC.CUSTOM.DOMAIN.", dns.Type(dns.TypeA)))

				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Res.Answer).Should(BeDNSRecord("ABC.CUSTOM.DOMAIN.", dns.TypeA, TTL, "192.168.143.123"))
				// will not delegate to next resolver
				m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
			})
		})
		AfterEach(func() {
			Expect(err).Should(Succeed())
		})
	})

	Describe("Delegating to next resolver", func() {
		When("no mapping for domain exist", func() {
			It("should delegate to next resolver", func() {
				resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))

				Expect(err).Should(Succeed())
				// delegate was executed
				m.AssertExpectations(GinkgoT())
			})
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(c).Should(HaveLen(3))
			})
		})

		When("resolver is disabled", func() {
			BeforeEach(func() {
				cfg = config.CustomDNSConfig{}
			})
			It("should return 'disabled'", func() {
				c := sut.Configuration()
				Expect(c).Should(HaveLen(1))
				Expect(c).Should(Equal([]string{"deactivated"}))
			})
		})
	})
})
