package resolver

import (
	"context"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/evt"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/redis"
	"github.com/0xERR0R/blocky/util"
	"github.com/alicebob/miniredis/v2"
	"github.com/creasty/defaults"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var (
	group1File, group2File, defaultGroupFile *TmpFile
	tmpDir                                   *TmpFolder
)

var _ = BeforeSuite(func() {
	tmpDir = NewTmpFolder("BlockingResolver")
	group1File = tmpDir.CreateStringFile("group1File", "DOMAIN1.com")
	group2File = tmpDir.CreateStringFile("group2File", "blocked2.com")
	defaultGroupFile = tmpDir.CreateStringFile("defaultGroupFile",
		"blocked3.com",
		"123.145.123.145",
		"2001:db8:85a3:08d3::370:7344",
		"badcnamedomain.com")
})

var _ = Describe("BlockingResolver", Label("blockingResolver"), func() {
	var (
		sut        *BlockingResolver
		sutConfig  config.Blocking
		m          *mockResolver
		mockAnswer *dns.Msg
		ctx        context.Context
		cancelFn   context.CancelFunc
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		sutConfig = config.Blocking{
			BlockType: "ZEROIP",
			BlockTTL:  config.Duration(time.Minute),
		}

		mockAnswer = new(dns.Msg)
	})

	JustBeforeEach(func() {
		var err error

		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)

		sut, err = NewBlockingResolver(ctx, sutConfig, nil, systemResolverBootstrap)
		Expect(err).Should(Succeed())
		sut.Next(m)
	})

	Describe("IsEnabled", func() {
		It("is false", func() {
			Expect(sut.IsEnabled()).Should(BeFalse())
		})
	})

	Describe("LogConfig", func() {
		It("should log something", func() {
			logger, hook := log.NewMockEntry()

			sut.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
		})
	})

	Describe("Events", func() {
		BeforeEach(func() {
			sutConfig = config.Blocking{
				BlockType: "ZEROIP",
				BlockTTL:  config.Duration(time.Minute),
				Denylists: map[string][]config.BytesSource{
					"gr1": config.NewBytesSources(group1File.Path),
					"gr2": config.NewBytesSources(group2File.Path),
				},
			}
		})
		When("List is refreshed", func() {
			It("event should be fired", func() {
				// recreate to trigger a reload
				_, err := NewBlockingResolver(ctx, sutConfig, nil, systemResolverBootstrap)
				Expect(err).Should(Succeed())
			})
		})
	})

	Describe("Blocking with full-qualified client name", func() {
		BeforeEach(func() {
			sutConfig = config.Blocking{
				BlockType: "ZEROIP",
				BlockTTL:  config.Duration(time.Minute),
				Denylists: map[string][]config.BytesSource{
					"gr1": config.NewBytesSources(group1File.Path),
					"gr2": config.NewBytesSources(group2File.Path),
				},
				ClientGroupsBlock: map[string][]string{
					"default":            {"gr1"},
					"full.qualified.com": {"gr2"},
				},
			}
		})

		When("Full-qualified group name is used", func() {
			It("should block request", func() {
				m.AnswerFn = func(t dns.Type, qName string) (*dns.Msg, error) {
					if t == dns.Type(dns.TypeA) && qName == "full.qualified.com." {
						return util.NewMsgWithAnswer(qName, 60*60, A, "192.168.178.39")
					}

					return nil, nil //nolint:nilnil
				}
				Bus().Publish(ApplicationStarted, "")
				Eventually(func(g Gomega) {
					g.Expect(sut.Resolve(ctx, newRequestWithClient("blocked2.com.", A, "192.168.178.39", "client1"))).
						Should(And(
							BeDNSRecord("blocked2.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 60)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReturnCode(dns.RcodeSuccess),
						))
				}, "10s", "1s").Should(Succeed())
			})
		})
	})

	Describe("Blocking with fast init strategy", func() {
		BeforeEach(func() {
			sutConfig = config.Blocking{
				BlockType: "ZEROIP",
				BlockTTL:  config.Duration(time.Minute),
				Denylists: map[string][]config.BytesSource{
					"gr1": {config.TextBytesSource("/regex/")},
				},
				ClientGroupsBlock: map[string][]string{
					"default": {"gr1"},
				},
				Loading: config.SourceLoading{
					Init: config.Init{Strategy: config.InitStrategyFast},
				},
			}
		})

		When("Domain is on the denylist", func() {
			It("should block request", func() {
				Eventually(sut.Resolve).
					WithContext(ctx).
					WithArguments(newRequestWithClient("regex.com.", dns.Type(dns.TypeA), "1.2.1.2", "client1")).
					Should(
						SatisfyAll(
							BeDNSRecord("regex.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 60)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
		})
	})

	Describe("Blocking requests", func() {
		BeforeEach(func() {
			sutConfig = config.Blocking{
				BlockTTL: config.Duration(6 * time.Hour),
				Denylists: map[string][]config.BytesSource{
					"gr1":          config.NewBytesSources(group1File.Path),
					"gr2":          config.NewBytesSources(group2File.Path),
					"defaultGroup": config.NewBytesSources(defaultGroupFile.Path),
				},
				ClientGroupsBlock: map[string][]string{
					"Client1":         {"gr1"},
					"client2,client3": {"gr1"},
					"client3":         {"gr2"},
					"192.168.178.55":  {"gr1"},
					"altName":         {"gr2"},
					"10.43.8.67/28":   {"gr1"},
					"wildcard[0-9]*":  {"gr1"},
					"default":         {"defaultGroup"},
				},
				BlockType: "ZeroIP",
			}
		})

		When("client name is defined in client groups block", func() {
			It("should block the A query if domain is on the denylist (single)", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "client1"))).
					Should(
						SatisfyAll(
							BeDNSRecord("domain1.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReason("BLOCKED (gr1)"),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("should block the A query if domain is on the denylist (multipart 1)", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "client2"))).
					Should(
						SatisfyAll(
							BeDNSRecord("domain1.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReason("BLOCKED (gr1)"),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("should block the A query if domain is on the denylist (multipart 2)", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "client3"))).
					Should(
						SatisfyAll(
							BeDNSRecord("domain1.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReason("BLOCKED (gr1)"),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("should block the A query if domain is on the denylist (merged)", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("blocked2.com.", A, "1.2.1.2", "client3"))).
					Should(
						SatisfyAll(
							BeDNSRecord("blocked2.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReason("BLOCKED (gr2)"),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("should block the AAAA query if domain is on the denylist", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", AAAA, "1.2.1.2", "client1"))).
					Should(
						SatisfyAll(
							BeDNSRecord("domain1.com.", AAAA, "::"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReason("BLOCKED (gr1)"),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("should block the HTTPS query if domain is on the denylist", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", HTTPS, "1.2.1.2", "client1"))).
					Should(HaveReturnCode(dns.RcodeNameError))
			})
			It("should block the MX query if domain is on the denylist", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", MX, "1.2.1.2", "client1"))).
					Should(HaveReturnCode(dns.RcodeNameError))
			})
		})

		When("Client ip is defined in client groups block", func() {
			It("should block the query if domain is on the denylist", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "192.168.178.55", "unknown"))).
					Should(
						SatisfyAll(
							BeDNSRecord("domain1.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReason("BLOCKED (gr1)"),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
		})
		When("Client CIDR (10.43.8.64 - 10.43.8.79) is defined in client groups block", func() {
			It("should not block the query for 10.43.8.63 if domain is on the denylist", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "10.43.8.63", "unknown"))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))

				// was delegated to next resolver
				m.AssertExpectations(GinkgoT())
			})
			It("should not block the query for 10.43.8.80 if domain is on the denylist", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "10.43.8.80", "unknown"))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))

				// was delegated to next resolver
				m.AssertExpectations(GinkgoT())
			})
		})

		When("Client CIDR (10.43.8.64 - 10.43.8.79) is defined in client groups block", func() {
			It("should block the query for 10.43.8.64 if domain is on the denylist", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "10.43.8.64", "unknown"))).
					Should(
						SatisfyAll(
							BeDNSRecord("domain1.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReason("BLOCKED (gr1)"),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("should block the query for 10.43.8.79 if domain is on the denylist", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "10.43.8.79", "unknown"))).
					Should(
						SatisfyAll(
							BeDNSRecord("domain1.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReason("BLOCKED (gr1)"),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
		})

		When("Client has multiple names and for each name a client group block definition exists", func() {
			It("should block query if domain is in one group", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "client1", "altname"))).
					Should(
						SatisfyAll(
							BeDNSRecord("domain1.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReason("BLOCKED (gr1)"),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("should block query if domain is in another group too", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("blocked2.com.", A, "1.2.1.2", "client1", "altName"))).
					Should(
						SatisfyAll(
							BeDNSRecord("blocked2.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReason("BLOCKED (gr2)"),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
		})
		When("Client name matches wildcard", func() {
			It("should block query if domain is in one group", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "wildcard1name"))).
					Should(
						SatisfyAll(
							BeDNSRecord("domain1.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReason("BLOCKED (gr1)"),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
		})

		When("Default group is defined", func() {
			It("should block domains from default group for each client", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
					Should(
						SatisfyAll(
							BeDNSRecord("blocked3.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReason("BLOCKED (defaultGroup)"),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
		})

		When("BlockType is NxDomain", func() {
			BeforeEach(func() {
				sutConfig = config.Blocking{
					BlockTTL: config.Duration(time.Minute),
					Denylists: map[string][]config.BytesSource{
						"defaultGroup": config.NewBytesSources(defaultGroupFile.Path),
					},
					ClientGroupsBlock: map[string][]string{
						"default": {"defaultGroup"},
					},
					BlockType: "NxDomain",
				}
			})

			It("should return NXDOMAIN if query is blocked", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReturnCode(dns.RcodeNameError),
							HaveReason("BLOCKED (defaultGroup)"),
						))
			})
		})

		When("BlockTTL is set", func() {
			BeforeEach(func() {
				sutConfig = config.Blocking{
					BlockType: "ZEROIP",
					Denylists: map[string][]config.BytesSource{
						"defaultGroup": config.NewBytesSources(defaultGroupFile.Path),
					},
					ClientGroupsBlock: map[string][]string{
						"default": {"defaultGroup"},
					},
					BlockTTL: config.Duration(time.Second * 1234),
				}
			})

			It("should return answer with specified TTL", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
					Should(
						SatisfyAll(
							BeDNSRecord("blocked3.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 1234)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveReason("BLOCKED (defaultGroup)"),
						))
			})

			When("BlockType is custom IP", func() {
				BeforeEach(func() {
					sutConfig.BlockType = "12.12.12.12"
				})

				It("should return custom IP with specified TTL", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("blocked3.com.", A, "12.12.12.12"),
								HaveTTL(BeNumerically("==", 1234)),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReturnCode(dns.RcodeSuccess),
								HaveReason("BLOCKED (defaultGroup)"),
							))
				})
			})
		})

		When("BlockType is custom IP", func() {
			BeforeEach(func() {
				sutConfig = config.Blocking{
					BlockTTL: config.Duration(6 * time.Hour),
					Denylists: map[string][]config.BytesSource{
						"defaultGroup": config.NewBytesSources(defaultGroupFile.Path),
					},
					ClientGroupsBlock: map[string][]string{
						"default": {"defaultGroup"},
					},
					BlockType: "12.12.12.12, 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
				}
			})

			It("should return ipv4 address for A query if query is blocked", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
					Should(
						SatisfyAll(
							BeDNSRecord("blocked3.com.", A, "12.12.12.12"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveReason("BLOCKED (defaultGroup)"),
						))
			})

			It("should return ipv6 address for AAAA query if query is blocked", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", AAAA, "1.2.1.2", "unknown"))).
					Should(
						SatisfyAll(
							BeDNSRecord("blocked3.com.", AAAA, "2001:db8:85a3::8a2e:370:7334"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveReason("BLOCKED (defaultGroup)"),
						))
			})
		})

		When("BlockType is custom IP only for ipv4", func() {
			BeforeEach(func() {
				sutConfig = config.Blocking{
					Denylists: map[string][]config.BytesSource{
						"defaultGroup": config.NewBytesSources(defaultGroupFile.Path),
					},
					ClientGroupsBlock: map[string][]string{
						"default": {"defaultGroup"},
					},
					BlockType: "12.12.12.12",
					BlockTTL:  config.Duration(6 * time.Hour),
				}
			})

			It("should use fallback for ipv6 and return zero ip", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", AAAA, "1.2.1.2", "unknown"))).
					Should(
						SatisfyAll(
							BeDNSRecord("blocked3.com.", AAAA, "::"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveReason("BLOCKED (defaultGroup)"),
						))
			})
		})

		When("Denylist contains IP", func() {
			When("IP4", func() {
				BeforeEach(func() {
					// return defined IP as response
					mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 300, A, "123.145.123.145")
				})
				It("should block query, if lookup result contains denylisted IP", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("example.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 21600)),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReturnCode(dns.RcodeSuccess),
								HaveReason("BLOCKED IP (defaultGroup)"),
							))
				})
			})
			When("IP6", func() {
				BeforeEach(func() {
					// return defined IP as response
					mockAnswer, _ = util.NewMsgWithAnswer(
						"example.com.", 300,
						AAAA, "2001:0db8:85a3:08d3::0370:7344",
					)
				})
				It("should block query, if lookup result contains denylisted IP", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("example.com.", AAAA, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", AAAA, "::"),
								HaveTTL(BeNumerically("==", 21600)),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReturnCode(dns.RcodeSuccess),
								HaveReason("BLOCKED IP (defaultGroup)"),
							))
				})
			})
		})

		When("denylist contains domain which is CNAME in response", func() {
			BeforeEach(func() {
				// reconfigure mock, to return CNAMEs
				rr1, _ := dns.NewRR("example.com 300 IN CNAME domain.com")
				rr2, _ := dns.NewRR("domain.com 300 IN CNAME badcnamedomain.com")
				rr3, _ := dns.NewRR("badcnamedomain.com 300 IN A 125.125.125.125")
				mockAnswer = new(dns.Msg)
				mockAnswer.Answer = []dns.RR{rr1, rr2, rr3}
			})
			It("should block the query, if response contains a CNAME with domain on a denylist", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("example.com.", A, "1.2.1.2", "unknown"))).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 21600)),
							HaveResponseType(ResponseTypeBLOCKED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveReason("BLOCKED CNAME (defaultGroup)"),
						))
			})
		})
	})

	Describe("Allowlisting", func() {
		When("Requested domain is on black and allowlist", func() {
			BeforeEach(func() {
				sutConfig = config.Blocking{
					BlockType:  "ZEROIP",
					BlockTTL:   config.Duration(time.Minute),
					Denylists:  map[string][]config.BytesSource{"gr1": config.NewBytesSources(group1File.Path)},
					Allowlists: map[string][]config.BytesSource{"gr1": config.NewBytesSources(group1File.Path)},
					ClientGroupsBlock: map[string][]string{
						"default": {"gr1"},
					},
				}
			})
			It("Should not be blocked", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "unknown"))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))

				// was delegated to next resolver
				m.AssertExpectations(GinkgoT())
			})
		})

		When("Only allowlist is defined", func() {
			BeforeEach(func() {
				sutConfig = config.Blocking{
					BlockType: "zeroIP",
					BlockTTL:  config.Duration(60 * time.Second),
					Allowlists: map[string][]config.BytesSource{
						"gr1": config.NewBytesSources(group1File.Path),
						"gr2": config.NewBytesSources(group2File.Path),
					},
					ClientGroupsBlock: map[string][]string{
						"default":    {"gr1"},
						"one-client": {"gr1"},
						"two-client": {"gr2"},
						"all-client": {"gr1", "gr2"},
					},
				}
			})
			It("should block everything else except domains on the allowlist with default group", func() {
				By("querying domain on the allowlist", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// was delegated to next resolver
					m.AssertExpectations(GinkgoT())
				})

				By("querying another domain, which is not on the allowlist", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("google.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("google.com.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 60)),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReturnCode(dns.RcodeSuccess),
								HaveReason("BLOCKED (ALLOWLIST ONLY)"),
							))

					Expect(m.Calls).Should(HaveLen(1))
				})
			})
			It("should block everything else except domains on the allowlist "+
				"if multiple allowlist only groups are defined", func() {
				By("querying domain on the allowlist", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "one-client"))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// was delegated to next resolver
					m.AssertExpectations(GinkgoT())
				})

				By("querying another domain, which is not on the allowlist", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("blocked2.com.", A, "1.2.1.2", "one-client"))).
						Should(
							SatisfyAll(
								BeDNSRecord("blocked2.com.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 60)),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReturnCode(dns.RcodeSuccess),
								HaveReason("BLOCKED (ALLOWLIST ONLY)"),
							))
					Expect(m.Calls).Should(HaveLen(1))
				})
			})
			It("should block everything else except domains on the allowlist "+
				"if multiple allowlist only groups are defined", func() {
				By("querying domain on the allowlist group 1", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "all-client"))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// was delegated to next resolver
					m.AssertExpectations(GinkgoT())
				})

				By("querying another domain, which is in the allowlist group 1", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("blocked2.com.", A, "1.2.1.2", "all-client"))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
					Expect(m.Calls).Should(HaveLen(2))
				})
			})
		})

		When("IP address is on black and allowlist", func() {
			BeforeEach(func() {
				sutConfig = config.Blocking{
					BlockType:  "ZEROIP",
					BlockTTL:   config.Duration(time.Minute),
					Denylists:  map[string][]config.BytesSource{"gr1": config.NewBytesSources(group1File.Path)},
					Allowlists: map[string][]config.BytesSource{"gr1": config.NewBytesSources(defaultGroupFile.Path)},
					ClientGroupsBlock: map[string][]string{
						"default": {"gr1"},
					},
				}
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 300, A, "123.145.123.145")
			})
			It("should not block if DNS answer contains IP from the allowlist", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("example.com.", A, "1.2.1.2", "unknown"))).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "123.145.123.145"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
				// was delegated to next resolver
				m.AssertExpectations(GinkgoT())
			})
		})
	})

	Describe("Delegate request to next resolver", func() {
		BeforeEach(func() {
			sutConfig = config.Blocking{
				BlockType: "ZEROIP",
				BlockTTL:  config.Duration(time.Minute),
				Denylists: map[string][]config.BytesSource{"gr1": config.NewBytesSources(group1File.Path)},
				ClientGroupsBlock: map[string][]string{
					"default": {"gr1"},
				},
			}
		})
		AfterEach(func() {
			// was delegated to next resolver
			m.AssertExpectations(GinkgoT())
		})
		When("domain is not on the denylist", func() {
			It("should delegate to next resolver", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("example.com.", A, "1.2.1.2", "unknown"))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
		})
		When("no lists defined", func() {
			BeforeEach(func() {
				sutConfig = config.Blocking{
					BlockType: "ZEROIP",
					BlockTTL:  config.Duration(time.Minute),
				}
			})
			It("should delegate to next resolver", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("example.com.", A, "1.2.1.2", "unknown"))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
		})
	})

	Describe("Control status via API", func() {
		BeforeEach(func() {
			sutConfig = config.Blocking{
				Denylists: map[string][]config.BytesSource{
					"defaultGroup": config.NewBytesSources(defaultGroupFile.Path),
					"group1":       config.NewBytesSources(group1File.Path),
				},
				ClientGroupsBlock: map[string][]string{
					"default": {"defaultGroup", "group1"},
				},
				BlockType: "ZeroIP",
			}
		})
		When("Disable blocking is called", func() {
			It("no query should be blocked", func() {
				By("Perform query to ensure that the blocking status is active (defaultGroup)", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("blocked3.com.", A, "0.0.0.0"),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReason("BLOCKED (defaultGroup)"),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})

				By("Perform query to ensure that the blocking status is active (group1)", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("domain1.com.", A, "0.0.0.0"),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReason("BLOCKED (group1)"),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})

				By("Calling Rest API to deactivate all groups", func() {
					err := sut.DisableBlocking(context.TODO(), 0, []string{})
					Expect(err).Should(Succeed())
				})

				By("perform the same query again (defaultGroup)", func() {
					// now is blocking disabled, query the url again
					Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
				})

				By("perform the same query again (group1)", func() {
					// now is blocking disabled, query the url again
					Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 2)
				})

				By("Calling Rest API to deactivate only defaultGroup", func() {
					err := sut.DisableBlocking(context.TODO(), 0, []string{"defaultGroup"})
					Expect(err).Should(Succeed())
				})

				By("perform the same query again (defaultGroup)", func() {
					// now is blocking disabled, query the url again
					Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 3)
				})

				By("Perform query to ensure that the blocking status is active (group1)", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("domain1.com.", A, "0.0.0.0"),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReason("BLOCKED (group1)"),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
			})
		})

		When("Disable blocking for all groups is called with a duration parameter", func() {
			It("No query should be blocked only for passed amount of time", func() {
				By("Perform query to ensure that the blocking status is active (defaultGroup)", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("blocked3.com.", A, "0.0.0.0"),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReason("BLOCKED (defaultGroup)"),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
				By("Perform query to ensure that the blocking status is active (group1)", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("domain1.com.", A, "0.0.0.0"),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReason("BLOCKED (group1)"),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})

				By("Calling Rest API to deactivate blocking for 0.5 sec", func() {
					enabled := make(chan bool, 1)
					err := Bus().SubscribeOnce(BlockingEnabledEvent, func(state bool) {
						enabled <- state
					})
					Expect(err).Should(Succeed())
					err = sut.DisableBlocking(context.TODO(), 500*time.Millisecond, []string{})
					Expect(err).Should(Succeed())
					Eventually(enabled, "1s").Should(Receive(BeFalse()))
				})

				By("perform the same query again to ensure that this query will not be blocked (defaultGroup)", func() {
					// now is blocking disabled, query the url again
					Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
				})
				By("perform the same query again to ensure that this query will not be blocked (group1)", func() {
					// now is blocking disabled, query the url again
					Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 2)
				})

				By("Wait 1 sec and perform the same query again, should be blocked now", func() {
					enabled := make(chan bool, 1)
					_ = Bus().SubscribeOnce(BlockingEnabledEvent, func(state bool) {
						enabled <- state
					})
					// wait 1 sec
					Eventually(enabled, "1s").Should(Receive(BeTrue()))

					Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("blocked3.com.", A, "0.0.0.0"),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReason("BLOCKED (defaultGroup)"),
								HaveReturnCode(dns.RcodeSuccess),
							))

					Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("domain1.com.", A, "0.0.0.0"),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReason("BLOCKED (group1)"),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
			})
		})

		When("Disable blocking for one group is called with a duration parameter", func() {
			It("No query should be blocked only for passed amount of time", func() {
				By("Perform query to ensure that the blocking status is active (defaultGroup)", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("blocked3.com.", A, "0.0.0.0"),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReason("BLOCKED (defaultGroup)"),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
				By("Perform query to ensure that the blocking status is active (group1)", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("domain1.com.", A, "0.0.0.0"),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReason("BLOCKED (group1)"),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})

				By("Calling Rest API to deactivate blocking for one group for 0.5 sec", func() {
					enabled := make(chan bool, 1)
					err := Bus().SubscribeOnce(BlockingEnabledEvent, func(state bool) {
						enabled <- false
					})
					Expect(err).Should(Succeed())
					err = sut.DisableBlocking(context.TODO(), 500*time.Millisecond, []string{"group1"})
					Expect(err).Should(Succeed())
					Eventually(enabled, "1s").Should(Receive(BeFalse()))
				})

				By("perform the same query again to ensure that this query will not be blocked (defaultGroup)", func() {
					// now is blocking disabled, query the url again
					Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("blocked3.com.", A, "0.0.0.0"),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReason("BLOCKED (defaultGroup)"),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
				By("perform the same query again to ensure that this query will not be blocked (group1)", func() {
					// now is blocking disabled, query the url again
					Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								HaveNoAnswer(),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
				})

				By("Wait 1 sec and perform the same query again, should be blocked now", func() {
					enabled := make(chan bool, 1)
					_ = Bus().SubscribeOnce(BlockingEnabledEvent, func(state bool) {
						enabled <- state
					})
					// wait 1 sec
					Eventually(enabled, "1s").Should(Receive(BeTrue()))

					Expect(sut.Resolve(ctx, newRequestWithClient("blocked3.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("blocked3.com.", A, "0.0.0.0"),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReason("BLOCKED (defaultGroup)"),
								HaveReturnCode(dns.RcodeSuccess),
							))

					Expect(sut.Resolve(ctx, newRequestWithClient("domain1.com.", A, "1.2.1.2", "unknown"))).
						Should(
							SatisfyAll(
								BeDNSRecord("domain1.com.", A, "0.0.0.0"),
								HaveResponseType(ResponseTypeBLOCKED),
								HaveReason("BLOCKED (group1)"),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
			})
		})

		When("Disable blocking is called with wrong group name", func() {
			It("should fail", func() {
				err := sut.DisableBlocking(context.TODO(), 500*time.Millisecond, []string{"unknownGroupName"})
				Expect(err).Should(HaveOccurred())
			})
		})

		When("Blocking status is called", func() {
			It("should return correct status", func() {
				By("enable blocking via API", func() {
					sut.EnableBlocking(context.TODO())
				})

				By("Query blocking status via API should return 'enabled'", func() {
					result := sut.BlockingStatus()
					Expect(result.Enabled).Should(BeTrue())
				})

				By("disable blocking via API", func() {
					err := sut.DisableBlocking(context.TODO(), 500*time.Millisecond, []string{})
					Expect(err).Should(Succeed())
				})

				By("Query blocking status via API again should return 'disabled'", func() {
					result := sut.BlockingStatus()

					Expect(result.Enabled).Should(BeFalse())
				})
			})
		})
	})

	Describe("Create resolver with wrong parameter", func() {
		When("Wrong blockType is used", func() {
			It("should return error", func() {
				_, err := NewBlockingResolver(ctx, config.Blocking{
					BlockType: "wrong",
				}, nil, systemResolverBootstrap)

				Expect(err).Should(
					MatchError("unknown blockType 'wrong', please use one of: ZeroIP, NxDomain or specify destination IP address(es)"))
			})
		})
		When("strategy is failOnError", func() {
			It("should fail if lists can't be downloaded", func() {
				_, err := NewBlockingResolver(ctx, config.Blocking{
					Denylists:  map[string][]config.BytesSource{"gr1": config.NewBytesSources("wrongPath")},
					Allowlists: map[string][]config.BytesSource{"allowlist": config.NewBytesSources("wrongPath")},
					Loading: config.SourceLoading{
						Init: config.Init{Strategy: config.InitStrategyFailOnError},
					},
					BlockType: "zeroIp",
				}, nil, systemResolverBootstrap)
				Expect(err).Should(HaveOccurred())
			})
		})
	})

	Describe("Redis is configured", func() {
		var redisServer *miniredis.Miniredis
		var redisClient *redis.Client
		var err error
		JustBeforeEach(func() {
			redisServer, err = miniredis.Run()

			Expect(err).Should(Succeed())

			var rcfg config.Redis
			err = defaults.Set(&rcfg)

			Expect(err).Should(Succeed())
			rcfg.Address = redisServer.Addr()
			redisClient, err = redis.New(context.TODO(), &rcfg)

			Expect(err).Should(Succeed())
			Expect(redisClient).ShouldNot(BeNil())
			sutConfig = config.Blocking{
				BlockType: "ZEROIP",
				BlockTTL:  config.Duration(time.Minute),
			}

			sut, err = NewBlockingResolver(ctx, sutConfig, redisClient, systemResolverBootstrap)
			Expect(err).Should(Succeed())
		})
		JustAfterEach(func() {
			redisServer.Close()
		})
		When("disable", func() {
			It("should return disable", func() {
				sut.EnableBlocking(context.TODO())

				redisMockMsg := &redis.EnabledMessage{
					State: false,
				}
				redisClient.EnabledChannel <- redisMockMsg

				Eventually(func() bool {
					return sut.BlockingStatus().Enabled
				}, "5s").Should(BeFalse())
			})
		})
		When("disable", func() {
			It("should return disable", func() {
				sut.EnableBlocking(context.TODO())
				redisMockMsg := &redis.EnabledMessage{
					State:  false,
					Groups: []string{"unknown"},
				}
				redisClient.EnabledChannel <- redisMockMsg

				Eventually(func() bool {
					return sut.BlockingStatus().Enabled
				}, "5s").Should(BeTrue())
			})
		})
		When("enable", func() {
			It("should return enable", func() {
				err = sut.DisableBlocking(context.TODO(), time.Hour, []string{})
				Expect(err).Should(Succeed())

				redisMockMsg := &redis.EnabledMessage{
					State: true,
				}
				redisClient.EnabledChannel <- redisMockMsg

				Eventually(func() bool {
					return sut.BlockingStatus().Enabled
				}, "5s").Should(BeTrue())
			})
		})
	})
})
