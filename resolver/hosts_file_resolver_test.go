package resolver

import (
	"context"
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

var _ = Describe("HostsFileResolver", func() {
	var (
		TTL = uint32(time.Now().Second())

		sut       *HostsFileResolver
		sutConfig config.HostsFileConfig
		m         *mockResolver
		tmpDir    *TmpFolder
		tmpFile   *TmpFile
		err       error
		resp      *Response

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

		tmpDir = NewTmpFolder("HostsFileResolver")
		Expect(tmpDir.Error).Should(Succeed())
		DeferCleanup(tmpDir.Clean)

		tmpFile = writeHostFile(tmpDir)
		Expect(tmpFile.Error).Should(Succeed())

		sutConfig = config.HostsFileConfig{
			Sources:        config.NewBytesSources(tmpFile.Path),
			HostsTTL:       config.Duration(time.Duration(TTL) * time.Second),
			FilterLoopback: true,
			Loading: config.SourceLoadingConfig{
				RefreshPeriod:      -1,
				MaxErrorsPerSource: 5,
			},
		}
	})

	JustBeforeEach(func() {
		sut, err = NewHostsFileResolver(ctx, sutConfig, systemResolverBootstrap)
		Expect(err).Should(Succeed())

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

	Describe("Using hosts file", func() {
		When("Hosts file cannot be located", func() {
			BeforeEach(func() {
				sutConfig = config.HostsFileConfig{
					Sources:  config.NewBytesSources("/this/file/does/not/exist"),
					HostsTTL: config.Duration(time.Duration(TTL) * time.Second),
				}
			})
			It("should not parse any hosts", func() {
				Expect(sut.cfg.Sources).ShouldNot(BeEmpty())
				Expect(sut.hosts.v4.hosts).Should(BeEmpty())
				Expect(sut.hosts.v6.hosts).Should(BeEmpty())
				Expect(sut.hosts.v4.aliases).Should(BeEmpty())
				Expect(sut.hosts.v6.aliases).Should(BeEmpty())
				Expect(sut.hosts.isEmpty()).Should(BeTrue())
			})
			It("should go to next resolver on query", func() {
				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
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
				sutConfig.Deprecated.Filepath = new(config.BytesSource)
				sutConfig.Sources = make([]config.BytesSource, 0)
			})
			JustBeforeEach(func() {
				err = sut.loadSources(ctx)
				Expect(err).Should(Succeed())
			})
			It("should go to next resolver on query", func() {
				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
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
				Expect(sut.hosts.v4.hosts).Should(HaveLen(5))
				Expect(sut.hosts.v6.hosts).Should(HaveLen(2))
				Expect(sut.hosts.v4.aliases).Should(HaveLen(4))
				Expect(sut.hosts.v6.aliases).Should(HaveLen(2))
			})

			When("filterLoopback is false", func() {
				BeforeEach(func() {
					sutConfig.FilterLoopback = false
				})

				It("should parse it successfully", func() {
					Expect(sut).ShouldNot(BeNil())
					Expect(sut.hosts.v4.hosts).Should(HaveLen(7))
					Expect(sut.hosts.v6.hosts).Should(HaveLen(3))
					Expect(sut.hosts.v4.aliases).Should(HaveLen(5))
					Expect(sut.hosts.v6.aliases).Should(HaveLen(2))
				})
			})
		})

		When("Hosts file has too many errors", func() {
			BeforeEach(func() {
				tmpFile = tmpDir.CreateStringFile("hosts-too-many-errors.txt",
					"invalidip localhost",
					"127.0.0.1 localhost", // ok
					"127.0.0.1 # no host",
					"127.0.0.1 invalidhost!",
					"a.b.c.d localhost",
					"127.0.0.x localhost",
					"256.0.0.1 localhost",
				)
				Expect(tmpFile.Error).Should(Succeed())

				sutConfig.Sources = config.NewBytesSources(tmpFile.Path)
			})

			It("should not be used", func() {
				Expect(sut).ShouldNot(BeNil())
				Expect(sut.cfg.Sources).ShouldNot(BeEmpty())
				Expect(sut.hosts.v4.hosts).Should(BeEmpty())
				Expect(sut.hosts.v6.hosts).Should(BeEmpty())
				Expect(sut.hosts.v4.aliases).Should(BeEmpty())
				Expect(sut.hosts.v6.aliases).Should(BeEmpty())
			})
		})

		When("IPv4 mapping is defined for a host", func() {
			It("defined ipv4 query should be resolved", func() {
				Expect(sut.Resolve(ctx, newRequest("ipv4host.", A))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeHOSTSFILE),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("ipv4host.", A, "192.168.2.1"),
							HaveTTL(BeNumerically("==", TTL)),
						))
			})
			It("defined ipv4 query for alias should be resolved", func() {
				Expect(sut.Resolve(ctx, newRequest("router2.", A))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeHOSTSFILE),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("router2.", A, "10.0.0.1"),
							HaveTTL(BeNumerically("==", TTL)),
						))
			})
			It("ipv4 query should return NOERROR and empty result", func() {
				Expect(sut.Resolve(ctx, newRequest("does.not.exist.", A))).
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
				Expect(sut.Resolve(ctx, newRequest("ipv6host.", AAAA))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeHOSTSFILE),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("ipv6host.", AAAA, "faaf:faaf:faaf:faaf::1"),
							HaveTTL(BeNumerically("==", TTL)),
						))
			})
			It("ipv6 query should return NOERROR and empty result", func() {
				Expect(sut.Resolve(ctx, newRequest("does.not.exist.", AAAA))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveReturnCode(dns.RcodeSuccess),
							HaveResponseType(ResponseTypeRESOLVED),
						))
			})
		})

		When("the domain is not known", func() {
			It("calls the next resolver", func() {
				resp, err = sut.Resolve(ctx, newRequest("not-in-hostsfile.tld.", A))
				Expect(err).Should(Succeed())
				Expect(resp).ShouldNot(HaveResponseType(ResponseTypeHOSTSFILE))
				m.AssertExpectations(GinkgoT())
			})
		})

		When("the question type is not handled", func() {
			It("calls the next resolver", func() {
				resp, err = sut.Resolve(ctx, newRequest("localhost.", MX))
				Expect(err).Should(Succeed())
				Expect(resp).ShouldNot(HaveResponseType(ResponseTypeHOSTSFILE))
				m.AssertExpectations(GinkgoT())
			})
		})

		When("Reverse DNS request is received", func() {
			It("should resolve the defined domain name", func() {
				By("ipv4 with one hostname", func() {
					Expect(sut.Resolve(ctx, newRequest("2.0.0.10.in-addr.arpa.", PTR))).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeHOSTSFILE),
								HaveReturnCode(dns.RcodeSuccess),
								BeDNSRecord("2.0.0.10.in-addr.arpa.", PTR, "router3."),
								HaveTTL(BeNumerically("==", TTL)),
							))
				})
				By("ipv4 with aliases", func() {
					Expect(sut.Resolve(ctx, newRequest("1.0.0.10.in-addr.arpa.", PTR))).
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
					Expect(sut.Resolve(ctx,
						newRequest("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.a.a.f.f.a.a.f.f.a.a.f.f.a.a.f.ip6.arpa.", PTR)),
					).
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

			It("should ignore invalid PTR", func() {
				resp, err = sut.Resolve(ctx, newRequest("2.0.0.10.in-addr.fail.arpa.", PTR))
				Expect(err).Should(Succeed())
				Expect(resp).ShouldNot(HaveResponseType(ResponseTypeHOSTSFILE))
				m.AssertExpectations(GinkgoT())
			})

			When("filterLoopback is true", func() {
				It("calls the next resolver", func() {
					resp, err = sut.Resolve(ctx, newRequest("1.0.0.127.in-addr.arpa.", PTR))
					Expect(err).Should(Succeed())
					Expect(resp).ShouldNot(HaveResponseType(ResponseTypeHOSTSFILE))
					m.AssertExpectations(GinkgoT())
				})
			})

			When("the IP is not known", func() {
				It("calls the next resolver", func() {
					resp, err = sut.Resolve(ctx, newRequest("255.255.255.255.in-addr.arpa.", PTR))
					Expect(err).Should(Succeed())
					Expect(resp).ShouldNot(HaveResponseType(ResponseTypeHOSTSFILE))
					m.AssertExpectations(GinkgoT())
				})
			})

			When("filterLoopback is false", func() {
				BeforeEach(func() {
					sutConfig.FilterLoopback = false
				})

				It("resolve the defined domain name", func() {
					Expect(sut.Resolve(ctx, newRequest("1.1.0.127.in-addr.arpa.", PTR))).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeHOSTSFILE),
								HaveReturnCode(dns.RcodeSuccess),
								WithTransform(ToAnswer, ContainElements(
									BeDNSRecord("1.1.0.127.in-addr.arpa.", PTR, "localhost2."),
									BeDNSRecord("1.1.0.127.in-addr.arpa.", PTR, "localhost2.local.lan."),
								)),
							))
				})
			})
		})
	})

	Describe("Delegating to next resolver", func() {
		When("no hosts file is provided", func() {
			It("should delegate to next resolver", func() {
				_, err = sut.Resolve(ctx, newRequest("example.com.", A))
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
		"faaf:faaf:faaf:faaf::2  dualhost    dualhost.local.lan",
		"192.168.2.2             dualhost    dualhost.local.lan",
		"10.0.0.1                router0 router1 router2",
		"10.0.0.2                router3     # Another comment",
		"10.0.0.3                router4#comment without a space",
		"10.0.0.4                            # Invalid entry",
		"300.300.300.300         invalid4    # Invalid IPv4",
		"abcd:efgh:ijkl::1       invalid6    # Invalid IPv6",
		"1.2.3.4                 localhost", // localhost name but not localhost IP

		// from https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
		"fe80::1%lo0             localhost", // interface name
	)
}
