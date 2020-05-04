package resolver

import (
	"blocky/config"
	. "blocky/helpertest"

	"net"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("CustomDNSResolver", func() {
	var (
		sut  ChainedResolver
		m    *resolverMock
		err  error
		resp *Response
	)

	BeforeEach(func() {
		sut = NewCustomDNSResolver(config.CustomDNSConfig{
			Mapping: map[string]net.IP{
				"custom.domain": net.ParseIP("192.168.143.123"),
				"ip6.domain":    net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
			}})
		m = &resolverMock{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("Resolving custom name via CustomDNSResolver", func() {
		When("Ip 4 mapping is defined for custom domain", func() {
			It("defined ip4 query should be resolved", func() {
				resp, err = sut.Resolve(newRequest("custom.domain.", dns.TypeA))

				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Res.Answer).Should(BeDNSRecord("custom.domain.", dns.TypeA, 3600, "192.168.143.123"))
			})
			It("ip6 query should return NXDOMAIN", func() {
				resp, err := sut.Resolve(newRequest("custom.domain.", dns.TypeAAAA))

				Expect(err).Should(BeNil())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
			})
		})
		When("Ip 6 mapping is defined for custom domain ", func() {
			It("ip6 query should be resolved", func() {
				resp, err = sut.Resolve(newRequest("ip6.domain.", dns.TypeAAAA))

				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Res.Answer).Should(BeDNSRecord("ip6.domain.", dns.TypeAAAA, 3600, "2001:db8:85a3::8a2e:370:7334"))
			})
		})
		When("Domain mapping is defined", func() {
			It("subdomain must also match", func() {
				resp, err = sut.Resolve(newRequest("ABC.CUSTOM.DOMAIN.", dns.TypeA))

				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Res.Answer).Should(BeDNSRecord("ABC.CUSTOM.DOMAIN.", dns.TypeA, 3600, "192.168.143.123"))
			})
		})
		AfterEach(func() {
			// will not delegate to next resolver
			m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
			Expect(err).Should(Succeed())
		})
	})

	Describe("Delegating to next resolver", func() {
		When("no mapping for domain exist", func() {
			It("should delegate to next resolver", func() {
				resp, err = sut.Resolve(newRequest("example.com.", dns.TypeA))

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
				Expect(c).Should(HaveLen(2))
			})
		})

		When("resolver is disabled", func() {
			BeforeEach(func() {
				sut = NewCustomDNSResolver(config.CustomDNSConfig{})
			})
			It("should return 'disabled''", func() {
				c := sut.Configuration()
				Expect(c).Should(HaveLen(1))
				Expect(c).Should(Equal([]string{"deactivated"}))
			})
		})
	})
})
