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
		sutMapping config.UpstreamGroups
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
		sutMapping = config.UpstreamGroups{
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
		sutConfig := config.UpstreamsConfig{
			Timeout: config.Duration(1000 * time.Millisecond),
			Groups:  sutMapping,
		}

		sut, err = NewParallelBestResolver(sutConfig, bootstrap, sutVerify)
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

	Describe("Name", func() {
		It("should not be empty", func() {
			Expect(sut.Name()).ShouldNot(BeEmpty())
		})
	})

	When("some default upstream resolvers cannot be reached", func() {
		It("should start normally", func() {
			mockUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
				response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 123, A, "123.124.122.122")

				return
			})
			defer mockUpstream.Close()

			upstream := config.UpstreamGroups{
				upstreamDefaultCfgName: {
					config.Upstream{
						Host: "wrong",
					},
					mockUpstream.Start(),
				},
			}

			_, err := NewParallelBestResolver(config.UpstreamsConfig{
				Groups: upstream,
			}, systemResolverBootstrap, verifyUpstreams)
			Expect(err).Should(Not(HaveOccurred()))
		})
	})

	When("no upstream resolvers can be reached", func() {
		BeforeEach(func() {
			bootstrap = newTestBootstrap(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

			sutMapping = config.UpstreamGroups{
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

					sutMapping = config.UpstreamGroups{
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
					sutMapping = config.UpstreamGroups{
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

					sutMapping = config.UpstreamGroups{
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
		When("only 1 upstream resolvers is defined", func() {
			BeforeEach(func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				DeferCleanup(mockUpstream.Close)

				sutMapping = config.UpstreamGroups{
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

				sut, _ = NewParallelBestResolver(config.UpstreamsConfig{Groups: config.UpstreamGroups{
					upstreamDefaultCfgName: {withError1, mockUpstream1.Start(), mockUpstream2.Start(), withError2},
				}},
					systemResolverBootstrap, noVerifyUpstreams)

				By("all resolvers have same weight for random -> equal distribution", func() {
					resolverCount := make(map[Resolver]int)

					for i := 0; i < 1000; i++ {
						var resolvers []*upstreamResolverStatus
						for _, r := range sut.resolversPerClient {
							resolvers = r
						}
						r1, r2 := pickRandom(resolvers)
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
						var resolvers []*upstreamResolverStatus
						for _, r := range sut.resolversPerClient {
							resolvers = r
						}
						r1, r2 := pickRandom(resolvers)
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

			r, err := NewParallelBestResolver(config.UpstreamsConfig{
				Groups: config.UpstreamGroups{"test": {{Host: "example.com"}}},
			}, b, verifyUpstreams)

			Expect(err).ShouldNot(Succeed())
			Expect(r).Should(BeNil())
		})
	})
})
