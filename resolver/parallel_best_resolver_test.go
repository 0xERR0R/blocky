package resolver

import (
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParallelBestResolver", Label("parallelBestResolver"), func() {
	const (
		verifyUpstreams   = true
		noVerifyUpstreams = false
	)

	var (
		sut        *ParallelBestResolver
		sutMapping config.ParallelBestMapping
		sutVerify  bool

		err error

		bootstrap *Bootstrap
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		sutMapping = config.ParallelBestMapping{
			upstreamDefaultCfgName: {
				config.Upstream{
					Host: "wrong",
				},
				config.Upstream{
					Host: "127.0.0.2",
				},
			},
		}

		sutVerify = noVerifyUpstreams

		bootstrap = systemResolverBootstrap
	})

	JustBeforeEach(func() {
		sutConfig := config.ParallelBestConfig{ExternalResolvers: sutMapping}

		sut, err = NewParallelBestResolver(sutConfig, bootstrap, sutVerify)
	})

	config.GetConfig().UpstreamTimeout = config.Duration(1000 * time.Millisecond)

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

	Describe("Name", func() {
		It("should not be empty", func() {
			Expect(sut.Name()).ShouldNot(BeEmpty())
		})
	})

	When("default upstream resolvers are not defined", func() {
		It("should fail on startup", func() {
			_, err := NewParallelBestResolver(config.ParallelBestConfig{
				ExternalResolvers: config.ParallelBestMapping{},
			}, nil, noVerifyUpstreams)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("no external DNS resolvers configured"))
		})
	})

	When("some default upstream resolvers cannot be reached", func() {
		It("should start normally", func() {
			mockUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
				response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 123, A, "123.124.122.122")

				return
			})
			defer mockUpstream.Close()

			upstream := config.ParallelBestMapping{
				upstreamDefaultCfgName: {
					config.Upstream{
						Host: "wrong",
					},
					mockUpstream.Start(),
				},
			}

			_, err := NewParallelBestResolver(config.ParallelBestConfig{
				ExternalResolvers: upstream,
			}, systemResolverBootstrap, verifyUpstreams)
			Expect(err).Should(Not(HaveOccurred()))
		})
	})

	When("no upstream resolvers can be reached", func() {
		BeforeEach(func() {
			bootstrap = newTestBootstrap(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

			sutMapping = config.ParallelBestMapping{
				upstreamDefaultCfgName: {
					config.Upstream{
						Host: "wrong",
					},
					config.Upstream{
						Host: "127.0.0.2",
					},
				},
			}
		})

		When("strict checking is enabled", func() {
			BeforeEach(func() {
				sutVerify = verifyUpstreams
			})
			It("should fail to start", func() {
				Expect(err).Should(HaveOccurred())
			})
		})

		When("strict checking is disabled", func() {
			BeforeEach(func() {
				sutVerify = noVerifyUpstreams
			})
			It("should start", func() {
				Expect(err).Should(Not(HaveOccurred()))
			})
		})
	})

	Describe("Resolving result from fastest upstream resolver", func() {
		When("2 Upstream resolvers are defined", func() {
			When("one resolver is fast and another is slow", func() {
				BeforeEach(func() {
					fastTestUpstream := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
					DeferCleanup(fastTestUpstream.Close)

					slowTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
						response, err := util.NewMsgWithAnswer("example.com.", 123, A, "123.124.122.123")
						time.Sleep(50 * time.Millisecond)

						Expect(err).Should(Succeed())

						return response
					})
					DeferCleanup(slowTestUpstream.Close)

					sutMapping = config.ParallelBestMapping{
						upstreamDefaultCfgName: {fastTestUpstream.Start(), slowTestUpstream.Start()},
					}
				})
				It("Should use result from fastest one", func() {
					request := newRequest("example.com.", A)
					Expect(sut.Resolve(request)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.122"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
			})
			When("one resolver is slow, but another returns an error", func() {
				BeforeEach(func() {
					withErrorUpstream := config.Upstream{Host: "wrong"}
					slowTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
						response, err := util.NewMsgWithAnswer("example.com.", 123, A, "123.124.122.123")
						time.Sleep(50 * time.Millisecond)

						Expect(err).Should(Succeed())

						return response
					})
					DeferCleanup(slowTestUpstream.Close)
					sutMapping = config.ParallelBestMapping{
						upstreamDefaultCfgName: {withErrorUpstream, slowTestUpstream.Start()},
					}
					Expect(err).Should(Succeed())
				})
				It("Should use result from successful resolver", func() {
					request := newRequest("example.com.", A)
					Expect(sut.Resolve(request)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.123"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
			})
			When("all resolvers return errors", func() {
				BeforeEach(func() {
					withError1 := config.Upstream{Host: "wrong"}
					withError2 := config.Upstream{Host: "wrong"}

					sutMapping = config.ParallelBestMapping{
						upstreamDefaultCfgName: {withError1, withError2},
					}
					Expect(err).Should(Succeed())
				})
				It("Should return error", func() {
					request := newRequest("example.com.", A)
					_, err = sut.Resolve(request)

					Expect(err).Should(HaveOccurred())
				})
			})
		})
		When("client specific resolvers are defined", func() {
			When("client name matches", func() {
				BeforeEach(func() {
					defaultMockUpstream := NewMockUDPUpstreamServer().
						WithAnswerRR("example.com 123 IN A 123.124.122.122")
					DeferCleanup(defaultMockUpstream.Close)

					clientSpecificExactMockUpstream := NewMockUDPUpstreamServer().
						WithAnswerRR("example.com 123 IN A 123.124.122.123")
					DeferCleanup(clientSpecificExactMockUpstream.Close)

					clientSpecificWildcardMockUpstream := NewMockUDPUpstreamServer().
						WithAnswerRR("example.com 123 IN A 123.124.122.124")
					DeferCleanup(clientSpecificWildcardMockUpstream.Close)

					clientSpecificIPMockUpstream := NewMockUDPUpstreamServer().
						WithAnswerRR("example.com 123 IN A 123.124.122.125")
					DeferCleanup(clientSpecificIPMockUpstream.Close)

					clientSpecificCIRDMockUpstream := NewMockUDPUpstreamServer().
						WithAnswerRR("example.com 123 IN A 123.124.122.126")
					DeferCleanup(clientSpecificCIRDMockUpstream.Close)

					sutMapping = config.ParallelBestMapping{
						upstreamDefaultCfgName: {defaultMockUpstream.Start()},
						"laptop":               {clientSpecificExactMockUpstream.Start()},
						"client-*-m":           {clientSpecificWildcardMockUpstream.Start()},
						"client[0-9]":          {clientSpecificWildcardMockUpstream.Start()},
						"192.168.178.33":       {clientSpecificIPMockUpstream.Start()},
						"10.43.8.67/28":        {clientSpecificCIRDMockUpstream.Start()},
					}
				})
				It("Should use default if client name or IP don't match", func() {
					request := newRequestWithClient("example.com.", A, "192.168.178.55", "test")

					Expect(sut.Resolve(request)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.122"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
				It("Should use client specific resolver if client name matches exact", func() {
					request := newRequestWithClient("example.com.", A, "192.168.178.55", "laptop")

					Expect(sut.Resolve(request)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.123"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
				It("Should use client specific resolver if client name matches with wildcard", func() {
					request := newRequestWithClient("example.com.", A, "192.168.178.55", "client-test-m")

					Expect(sut.Resolve(request)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.124"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
				It("Should use client specific resolver if client name matches with range wildcard", func() {
					request := newRequestWithClient("example.com.", A, "192.168.178.55", "client7")

					Expect(sut.Resolve(request)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.124"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
				It("Should use client specific resolver if client IP matches", func() {
					request := newRequestWithClient("example.com.", A, "192.168.178.33", "cl")

					Expect(sut.Resolve(request)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.125"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
				It("Should use client specific resolver if client IP/name matches", func() {
					request := newRequestWithClient("example.com.", A, "192.168.178.33", "192.168.178.33")

					Expect(sut.Resolve(request)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.125"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
				It("Should use client specific resolver if client's CIDR (10.43.8.64 - 10.43.8.79) matches", func() {
					request := newRequestWithClient("example.com.", A, "10.43.8.64", "cl")

					Expect(sut.Resolve(request)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.126"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
			})
		})
		When("only 1 upstream resolvers is defined", func() {
			BeforeEach(func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				DeferCleanup(mockUpstream.Close)

				sutMapping = config.ParallelBestMapping{
					upstreamDefaultCfgName: {
						mockUpstream.Start(),
					},
				}
			})
			It("Should use result from defined resolver", func() {
				request := newRequest("example.com.", A)

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "123.124.122.122"),
							HaveTTL(BeNumerically("==", 123)),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
		})
	})

	Describe("Weighted random on resolver selection", func() {
		When("5 upstream resolvers are defined", func() {
			It("should use 2 random peeked resolvers, weighted with last error timestamp", func() {
				withError1 := config.Upstream{Host: "wrong1"}
				withError2 := config.Upstream{Host: "wrong2"}

				mockUpstream1 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				DeferCleanup(mockUpstream1.Close)

				mockUpstream2 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				DeferCleanup(mockUpstream2.Close)

				sut, _ := NewParallelBestResolver(config.ParallelBestConfig{ExternalResolvers: config.ParallelBestMapping{
					upstreamDefaultCfgName: {withError1, mockUpstream1.Start(), mockUpstream2.Start(), withError2},
				}}, systemResolverBootstrap, noVerifyUpstreams)

				By("all resolvers have same weight for random -> equal distribution", func() {
					resolverCount := make(map[Resolver]int)

					for i := 0; i < 1000; i++ {
						r1, r2 := pickRandom(sut.resolversForClient(newRequestWithClient(
							"example.com", A, "123.123.100.100",
						)))
						res1 := r1.resolver
						res2 := r2.resolver
						Expect(res1).ShouldNot(Equal(res2))

						resolverCount[res1]++
						resolverCount[res2]++
					}
					for _, v := range resolverCount {
						// should be 500 ± 100
						Expect(v).Should(BeNumerically("~", 500, 100))
					}
				})
				By("perform 10 request, error upstream's weight will be reduced", func() {
					// perform 10 requests
					for i := 0; i < 100; i++ {
						request := newRequest("example.com.", A)
						_, _ = sut.Resolve(request)
					}
				})

				By("Resolvers without errors should be selected often", func() {
					resolverCount := make(map[*UpstreamResolver]int)

					for i := 0; i < 100; i++ {
						r1, r2 := pickRandom(sut.resolversForClient(newRequestWithClient(
							"example.com", A, "123.123.100.100",
						)))
						res1 := r1.resolver.(*UpstreamResolver)
						res2 := r2.resolver.(*UpstreamResolver)
						Expect(res1).ShouldNot(Equal(res2))

						resolverCount[res1]++
						resolverCount[res2]++
					}
					for k, v := range resolverCount {
						if strings.Contains(k.String(), "wrong") {
							// error resolvers: should be 0 - 10
							Expect(v).Should(BeNumerically("~", 0, 10))
						} else {
							// should be 90 ± 10
							Expect(v).Should(BeNumerically("~", 90, 10))
						}
					}
				})
			})
		})
	})

	When("upstream is invalid", func() {
		It("errors during construction", func() {
			b := newTestBootstrap(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

			r, err := NewParallelBestResolver(config.ParallelBestConfig{
				ExternalResolvers: config.ParallelBestMapping{"test": {{Host: "example.com"}}},
			}, b, verifyUpstreams)

			Expect(err).ShouldNot(Succeed())
			Expect(r).Should(BeNil())
		})
	})
})
