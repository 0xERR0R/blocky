package resolver

import (
	"fmt"
	"math/rand"

	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("HostsFileResolver", func() {
	var (
		sut  *HostsFileResolver
		m    *resolverMock
		err  error
		resp *Response
	)
	BeforeEach(func() {
		sut = NewHostsFileResolver("../testdata/hosts.txt").(*HostsFileResolver)
		m = &resolverMock{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("Using hosts file", func() {
		When("Hosts file cannot be located", func() {
			BeforeEach(func() {
				//nolint:gosec
				sut = NewHostsFileResolver(fmt.Sprintf("/tmp/blocky/file-%d", rand.Uint64())).(*HostsFileResolver)
			})
			It("should return an error", func() {
				err = sut.parseHostsFile()
				Expect(err).Should(Not(Succeed()))
			})
			It("should return an error on query", func() {
				resp, err = sut.Resolve(newRequest("localhost.", dns.TypeA))
				Expect(err).Should(Not(Succeed()))
			})
		})

		When("Hosts file is not set", func() {
			BeforeEach(func() {
				sut = NewHostsFileResolver("").(*HostsFileResolver)
				m = &resolverMock{}
				m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
				sut.Next(m)
			})
			It("should not return an error", func() {
				err = sut.parseHostsFile()
				Expect(err).Should(Succeed())
			})
			It("should go to next resolver on query", func() {
				resp, err = sut.Resolve(newRequest("example.com.", dns.TypeA))
				Expect(err).Should(Succeed())
				m.AssertExpectations(GinkgoT())
			})
		})

		When("Hosts file can be located", func() {
			It("should parse it successfully", func() {
				err = sut.parseHostsFile()
				Expect(err).Should(Succeed())
				Expect(sut.hosts).Should(HaveLen(7))
			})
		})

		When("IPv4 mapping is defined for a host", func() {
			It("defined ipv4 query should be resolved", func() {
				resp, err = sut.Resolve(newRequest("ipv4host.", dns.TypeA))
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.RType).Should(Equal(ResponseTypeHOSTSFILE))
				Expect(resp.Res.Answer).Should(BeDNSRecord("ipv4host.", dns.TypeA, 3600, "192.168.2.1"))
			})
			It("defined ipv4 query for alias should be resolved", func() {
				resp, err = sut.Resolve(newRequest("router2.", dns.TypeA))
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.RType).Should(Equal(ResponseTypeHOSTSFILE))
				Expect(resp.Res.Answer).Should(BeDNSRecord("router2.", dns.TypeA, 3600, "10.0.0.1"))
			})
			It("ipv4 query should return NOERROR and empty result", func() {
				resp, err = sut.Resolve(newRequest("does.not.exist.", dns.TypeA))
				Expect(err).Should(BeNil())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Res.Answer).Should(HaveLen(0))
			})
		})

		When("IPv6 mapping is defined for a host", func() {
			It("defined ipv6 query should be resolved", func() {
				resp, err = sut.Resolve(newRequest("ipv6host.", dns.TypeAAAA))
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.RType).Should(Equal(ResponseTypeHOSTSFILE))
				Expect(resp.Res.Answer).Should(BeDNSRecord("ipv6host.", dns.TypeAAAA, 3600, "faaf:faaf:faaf:faaf::1"))
			})
			It("ipv6 query should return NOERROR and empty result", func() {
				resp, err = sut.Resolve(newRequest("does.not.exist.", dns.TypeAAAA))
				Expect(err).Should(BeNil())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Res.Answer).Should(HaveLen(0))
			})
		})

		When("Reverse DNS request is received", func() {
			It("should resolve the defined domain name", func() {
				By("ipv4", func() {
					resp, err = sut.Resolve(newRequest("2.0.0.10.in-addr.arpa.", dns.TypePTR))
					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeHOSTSFILE))
					Expect(resp.Res.Answer).Should(HaveLen(1))
					Expect(resp.Res.Answer).Should(BeDNSRecord("2.0.0.10.in-addr.arpa.", dns.TypePTR, 3600, "router3."))
				})
				By("ipv6", func() {
					resp, err = sut.Resolve(newRequest("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.a.a.f.f.a.a.f.f.a.a.f.f.a.a.f.ip6.arpa.",
						dns.TypePTR))
					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeHOSTSFILE))
					Expect(resp.Res.Answer).Should(HaveLen(1))
					Expect(resp.Res.Answer).Should(
						BeDNSRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.a.a.f.f.a.a.f.f.a.a.f.f.a.a.f.ip6.arpa.",
							dns.TypePTR, 3600, "ipv6host."))
				})
			})
		})
	})

	Describe("Configuration output", func() {
		When("hosts file is provided", func() {
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(c).Should(HaveLen(1))
			})
		})

		When("hosts file is not provided", func() {
			BeforeEach(func() {
				sut = NewHostsFileResolver("").(*HostsFileResolver)
			})
			It("should return 'disabled'", func() {
				c := sut.Configuration()
				Expect(c).Should(HaveLen(1))
				Expect(c).Should(Equal([]string{"deactivated"}))
			})
		})
	})

	Describe("Delegating to next resolver", func() {
		When("no hosts file is provided", func() {
			It("should delegate to next resolver", func() {
				resp, err = sut.Resolve(newRequest("example.com.", dns.TypeA))
				Expect(err).Should(Succeed())
				// delegate was executed
				m.AssertExpectations(GinkgoT())
			})
		})
	})
})
