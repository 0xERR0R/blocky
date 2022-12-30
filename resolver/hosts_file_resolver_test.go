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
		sut     *HostsFileResolver
		m       *mockResolver
		tmpDir  *TmpFolder
		tmpFile *TmpFile
	)

	TTL := uint32(time.Now().Second())

	BeforeEach(func() {
		tmpDir = NewTmpFolder("HostsFileResolver")
		Expect(tmpDir.Error).Should(Succeed())
		DeferCleanup(tmpDir.Clean)

		tmpFile = writeHostFile(tmpDir)
		Expect(tmpFile.Error).Should(Succeed())

		cfg := config.HostsFileConfig{
			Filepath:       tmpFile.Path,
			HostsTTL:       config.Duration(time.Duration(TTL) * time.Second),
			RefreshPeriod:  config.Duration(30 * time.Minute),
			FilterLoopback: true,
		}
		sut = NewHostsFileResolver(cfg)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("Using hosts file", func() {
		When("Hosts file cannot be located", func() {
			BeforeEach(func() {
				sut = NewHostsFileResolver(config.HostsFileConfig{
					Filepath: fmt.Sprintf("/tmp/blocky/file-%d", rand.Uint64()),
					HostsTTL: config.Duration(time.Duration(TTL) * time.Second),
				})
				m = &mockResolver{}
				m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
				sut.Next(m)
			})
			It("should not parse any hosts", func() {
				Expect(sut.HostsFilePath).Should(BeEmpty())
				Expect(sut.hosts).Should(HaveLen(0))
			})
			It("should go to next resolver on query", func() {
				Expect(sut.Resolve(newRequest("example.com.", A))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
				m.AssertExpectations(GinkgoT())
			})
		})

		When("Hosts file is not set", func() {
			BeforeEach(func() {
				sut = NewHostsFileResolver(config.HostsFileConfig{})
				m = &mockResolver{}
				m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
				sut.Next(m)
			})
			It("should not return an error", func() {
				err := sut.parseHostsFile()
				Expect(err).Should(Succeed())
			})
			It("should go to next resolver on query", func() {
				Expect(sut.Resolve(newRequest("example.com.", A))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
				m.AssertExpectations(GinkgoT())
			})
		})

		When("Hosts file can be located", func() {
			It("should parse it successfully", func() {
				Expect(sut).ShouldNot(BeNil())
				Expect(sut.hosts).Should(HaveLen(4))
			})
		})

		When("IPv4 mapping is defined for a host", func() {
			It("defined ipv4 query should be resolved", func() {
				Expect(sut.Resolve(newRequest("ipv4host.", A))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeHOSTSFILE),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("ipv4host.", A, "192.168.2.1"),
							HaveTTL(BeNumerically("==", TTL)),
						))
			})
			It("defined ipv4 query for alias should be resolved", func() {
				Expect(sut.Resolve(newRequest("router2.", A))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeHOSTSFILE),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("router2.", A, "10.0.0.1"),
							HaveTTL(BeNumerically("==", TTL)),
						))
			})
			It("ipv4 query should return NOERROR and empty result", func() {
				Expect(sut.Resolve(newRequest("does.not.exist.", A))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveReturnCode(dns.RcodeSuccess),
							HaveResponseType(ResponseTypeRESOLVED),
						))
			})
		})

		When("IPv6 mapping is defined for a host", func() {
			It("defined ipv6 query should be resolved", func() {
				Expect(sut.Resolve(newRequest("ipv6host.", AAAA))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeHOSTSFILE),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("ipv6host.", AAAA, "faaf:faaf:faaf:faaf::1"),
							HaveTTL(BeNumerically("==", TTL)),
						))
			})
			It("ipv6 query should return NOERROR and empty result", func() {
				Expect(sut.Resolve(newRequest("does.not.exist.", AAAA))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveReturnCode(dns.RcodeSuccess),
							HaveResponseType(ResponseTypeRESOLVED),
						))
			})
		})

		When("Reverse DNS request is received", func() {
			It("should resolve the defined domain name", func() {
				By("ipv4 with one hostname", func() {
					Expect(sut.Resolve(newRequest("2.0.0.10.in-addr.arpa.", PTR))).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeHOSTSFILE),
								HaveReturnCode(dns.RcodeSuccess),
								BeDNSRecord("2.0.0.10.in-addr.arpa.", PTR, "router3."),
								HaveTTL(BeNumerically("==", TTL)),
							))
				})
				By("ipv4 with aliases", func() {
					Expect(sut.Resolve(newRequest("1.0.0.10.in-addr.arpa.", PTR))).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeHOSTSFILE),
								HaveReturnCode(dns.RcodeSuccess),
								WithTransform(ToAnswer, ContainElements(
									BeDNSRecord("1.0.0.10.in-addr.arpa.", PTR, "router0."),
									BeDNSRecord("1.0.0.10.in-addr.arpa.", PTR, "router1."),
									BeDNSRecord("1.0.0.10.in-addr.arpa.", PTR, "router2."),
								)),
							))
				})
				By("ipv6", func() {
					Expect(sut.Resolve(newRequest("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.a.a.f.f.a.a.f.f.a.a.f.f.a.a.f.ip6.arpa.", PTR))).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeHOSTSFILE),
								HaveReturnCode(dns.RcodeSuccess),
								WithTransform(ToAnswer, ContainElements(
									BeDNSRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.a.a.f.f.a.a.f.f.a.a.f.f.a.a.f.ip6.arpa.",
										PTR, "ipv6host."),
									BeDNSRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.a.a.f.f.a.a.f.f.a.a.f.f.a.a.f.ip6.arpa.",
										PTR, "ipv6host.local.lan."),
								)),
							))
				})
			})
		})
	})

	Describe("Configuration output", func() {
		When("hosts file is provided", func() {
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(len(c)).Should(BeNumerically(">", 1))
			})
		})

		When("hosts file is not provided", func() {
			BeforeEach(func() {
				sut = NewHostsFileResolver(config.HostsFileConfig{})
			})
			It("should return 'disabled'", func() {
				c := sut.Configuration()
				Expect(c).Should(ContainElement(configStatusDisabled))
			})
		})
	})

	Describe("Delegating to next resolver", func() {
		When("no hosts file is provided", func() {
			It("should delegate to next resolver", func() {
				_, err := sut.Resolve(newRequest("example.com.", A))
				Expect(err).Should(Succeed())
				// delegate was executed
				m.AssertExpectations(GinkgoT())
			})
		})
	})
})

func writeHostFile(tmpDir *TmpFolder) *TmpFile {
	return tmpDir.CreateStringFile("hosts.txt",
		"# Random comment",
		"127.0.0.1               localhost",
		"127.0.1.1               localhost2  localhost2.local.lan",
		"::1                     localhost",
		"# Two empty lines to follow",
		"",
		"",
		"faaf:faaf:faaf:faaf::1  ipv6host    ipv6host.local.lan",
		"192.168.2.1             ipv4host    ipv4host.local.lan",
		"10.0.0.1                router0 router1 router2",
		"10.0.0.2                router3     # Another comment",
		"10.0.0.3                            # Invalid entry",
		"300.300.300.300         invalid4    # Invalid IPv4",
		"abcd:efgh:ijkl::1       invalid6    # Invalud IPv6")
}
