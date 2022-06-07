package resolver

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("HostsFileResolver", func() {
	var (
		sut  *HostsFileResolver
		m    *MockResolver
		err  error
		resp *Response
	)

	TTL := uint32(time.Now().Second())

	BeforeEach(func() {
		cfg := config.HostsFileConfig{
			Filepath:      "../testdata/hosts.txt",
			HostsTTL:      config.Duration(time.Duration(TTL) * time.Second),
			RefreshPeriod: config.Duration(30 * time.Minute),
		}
		sut = NewHostsFileResolver(cfg).(*HostsFileResolver)
		m = &MockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("Using hosts file", func() {
		When("Hosts file cannot be located", func() {
			BeforeEach(func() {
				sut = NewHostsFileResolver(config.HostsFileConfig{
					//nolint:gosec
					Filepath: fmt.Sprintf("/tmp/blocky/file-%d", rand.Uint64()),
					HostsTTL: config.Duration(time.Duration(TTL) * time.Second),
				}).(*HostsFileResolver)
				m = &MockResolver{}
				m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
				sut.Next(m)
			})
			It("should not parse any hosts", func() {
				Expect(sut.HostsFilePath).Should(BeEmpty())
				Expect(sut.hosts).Should(HaveLen(0))
			})
			It("should go to next resolver on query", func() {
				resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
				Expect(err).Should(Succeed())
				m.AssertExpectations(GinkgoT())
			})
		})

		When("Hosts file is not set", func() {
			BeforeEach(func() {
				sut = NewHostsFileResolver(config.HostsFileConfig{}).(*HostsFileResolver)
				m = &MockResolver{}
				m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
				sut.Next(m)
			})
			It("should not return an error", func() {
				err = sut.parseHostsFile()
				Expect(err).Should(Succeed())
			})
			It("should go to next resolver on query", func() {
				resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
				Expect(err).Should(Succeed())
				m.AssertExpectations(GinkgoT())
			})
		})

		When("Hosts file can be located", func() {
			It("should parse it successfully", func() {
				Expect(sut).Should(Not(BeNil()))
				Expect(sut.hosts).Should(HaveLen(7))
			})
		})

		When("IPv4 mapping is defined for a host", func() {
			It("defined ipv4 query should be resolved", func() {
				resp, err = sut.Resolve(newRequest("ipv4host.", dns.Type(dns.TypeA)))
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.RType).Should(Equal(ResponseTypeHOSTSFILE))
				Expect(resp.Res.Answer).Should(BeDNSRecord("ipv4host.", dns.TypeA, TTL, "192.168.2.1"))
			})
			It("defined ipv4 query for alias should be resolved", func() {
				resp, err = sut.Resolve(newRequest("router2.", dns.Type(dns.TypeA)))
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.RType).Should(Equal(ResponseTypeHOSTSFILE))
				Expect(resp.Res.Answer).Should(BeDNSRecord("router2.", dns.TypeA, TTL, "10.0.0.1"))
			})
			It("ipv4 query should return NOERROR and empty result", func() {
				resp, err = sut.Resolve(newRequest("does.not.existdns.Type(.", dns.Type(dns.TypeA)))
				Expect(err).Should(BeNil())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Res.Answer).Should(HaveLen(0))
			})
		})

		When("IPv6 mapping is defined for a host", func() {
			It("defined ipv6 query should be resolved", func() {
				resp, err = sut.Resolve(newRequest("ipv6host.", dns.Type(dns.TypeAAAA)))
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.RType).Should(Equal(ResponseTypeHOSTSFILE))
				Expect(resp.Res.Answer).Should(BeDNSRecord("ipv6host.", dns.TypeAAAA, TTL, "faaf:faaf:faaf:faaf::1"))
			})
			It("ipv6 query should return NOERROR and empty result", func() {
				resp, err = sut.Resolve(newRequest("does.not.existdns.Type(.", dns.Type(dns.TypeAAAA)))
				Expect(err).Should(BeNil())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Res.Answer).Should(HaveLen(0))
			})
		})

		When("Reverse DNS request is received", func() {
			It("should resolve the defined domain name", func() {
				By("ipv4 with one hostname", func() {
					resp, err = sut.Resolve(newRequest("2.0.0.10.in-addr.arpa.", dns.Type(dns.TypePTR)))
					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeHOSTSFILE))
					Expect(resp.Res.Answer).Should(HaveLen(1))
					Expect(resp.Res.Answer).Should(BeDNSRecord("2.0.0.10.in-addr.arpa.", dns.TypePTR, TTL, "router3."))
				})
				By("ipv4 with aliases", func() {
					resp, err = sut.Resolve(newRequest("1.0.0.10.in-addr.arpa.", dns.Type(dns.TypePTR)))
					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeHOSTSFILE))
					Expect(resp.Res.Answer).Should(HaveLen(3))
					Expect(resp.Res.Answer[0]).Should(BeDNSRecord("1.0.0.10.in-addr.arpa.", dns.TypePTR, TTL, "router0."))
					Expect(resp.Res.Answer[1]).Should(BeDNSRecord("1.0.0.10.in-addr.arpa.", dns.TypePTR, TTL, "router1."))
					Expect(resp.Res.Answer[2]).Should(BeDNSRecord("1.0.0.10.in-addr.arpa.", dns.TypePTR, TTL, "router2."))
				})
				By("ipv6", func() {
					resp, err = sut.Resolve(newRequest("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.a.a.f.f.a.a.f.f.a.a.f.f.a.a.f.ip6.arpa.",
						dns.Type(dns.TypePTR)))
					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeHOSTSFILE))
					Expect(resp.Res.Answer).Should(HaveLen(2))
					Expect(resp.Res.Answer[0]).Should(
						BeDNSRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.a.a.f.f.a.a.f.f.a.a.f.f.a.a.f.ip6.arpa.",
							dns.TypePTR, TTL, "ipv6host."))
					Expect(resp.Res.Answer[1]).Should(
						BeDNSRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.a.a.f.f.a.a.f.f.a.a.f.f.a.a.f.ip6.arpa.",
							dns.TypePTR, TTL, "ipv6host.local.lan."))
				})
			})
		})
	})

	Describe("Configuration output", func() {
		When("hosts file is provided", func() {
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(c).Should(HaveLen(3))
			})
		})

		When("hosts file is not provided", func() {
			BeforeEach(func() {
				sut = NewHostsFileResolver(config.HostsFileConfig{}).(*HostsFileResolver)
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
				resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
				Expect(err).Should(Succeed())
				// delegate was executed
				m.AssertExpectations(GinkgoT())
			})
		})
	})
})
