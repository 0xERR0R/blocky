package resolver

import (
	"context"
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
		sut       *ParallelBestResolver
		upstreams []config.Upstream
		sutVerify bool
		ctx       context.Context
		cancelFn  context.CancelFunc

		err error

		bootstrap *Bootstrap
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		config.GetConfig().Upstreams.Strategy = config.UpstreamStrategyParallelBest

		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		upstreams = []config.Upstream{{Host: "wrong"}, {Host: "127.0.0.2"}}

		sutVerify = noVerifyUpstreams

		bootstrap = systemResolverBootstrap
	})

	JustBeforeEach(func() {
		sutConfig := config.UpstreamGroup{
			Name:      upstreamDefaultCfgName,
			Upstreams: upstreams,
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
		It("should contain correct resolver", func() {
			Expect(sut.Name()).ShouldNot(BeEmpty())
			Expect(sut.Name()).Should(ContainSubstring(parallelResolverType))
		})
	})

	When("some default upstream resolvers cannot be reached", func() {
		It("should start normally", func() {
			mockUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
				response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 123, A, "123.124.122.122")

				return
			})
			defer mockUpstream.Close()

			upstreams := []config.Upstream{
				{Host: "wrong"},
				mockUpstream.Start(),
			}

			_, err := NewParallelBestResolver(config.UpstreamGroup{
				Name:      upstreamDefaultCfgName,
				Upstreams: upstreams,
			},
				systemResolverBootstrap, verifyUpstreams)
			Expect(err).Should(Not(HaveOccurred()))
		})
	})

	When("no upstream resolvers can be reached", func() {
		BeforeEach(func() {
			bootstrap = newTestBootstrap(ctx, &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

			upstreams = []config.Upstream{{Host: "wrong"}, {Host: "127.0.0.2"}}
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

					upstreams = []config.Upstream{fastTestUpstream.Start(), slowTestUpstream.Start()}
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
				var slowTestUpstream *MockUDPUpstreamServer
				BeforeEach(func() {
					slowTestUpstream = NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
						response, err := util.NewMsgWithAnswer("example.com.", 123, A, "123.124.122.123")
						time.Sleep(50 * time.Millisecond)

						Expect(err).Should(Succeed())

						return response
					})
					DeferCleanup(slowTestUpstream.Close)
					upstreams = []config.Upstream{{Host: "wrong"}, slowTestUpstream.Start()}
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

					upstreams = []config.Upstream{withError1, withError2}
					Expect(err).Should(Succeed())
				})
				It("Should return error", func() {
					Expect(err).Should(Succeed())
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

				upstreams = []config.Upstream{mockUpstream.Start()}
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

				sut, _ = NewParallelBestResolver(config.UpstreamGroup{
					Name:      upstreamDefaultCfgName,
					Upstreams: []config.Upstream{withError1, mockUpstream1.Start(), mockUpstream2.Start(), withError2},
				},
					systemResolverBootstrap, noVerifyUpstreams)

				By("all resolvers have same weight for random -> equal distribution", func() {
					resolverCount := make(map[Resolver]int)

					for i := 0; i < 1000; i++ {
						resolvers := pickRandom(sut.resolvers, parallelBestResolverCount)
						res1 := resolvers[0].resolver
						res2 := resolvers[1].resolver
						Expect(res1).ShouldNot(Equal(res2))

						resolverCount[res1]++
						resolverCount[res2]++
					}
					for _, v := range resolverCount {
						// should be 500 ± 50
						Expect(v).Should(BeNumerically("~", 500, 75))
					}
				})
				By("perform 100 request, error upstream's weight will be reduced", func() {
					for i := 0; i < 100; i++ {
						request := newRequest("example.com.", A)
						_, _ = sut.Resolve(request)
					}
				})

				By("Resolvers without errors should be selected often", func() {
					resolverCount := make(map[*UpstreamResolver]int)

					for i := 0; i < 100; i++ {
						resolvers := pickRandom(sut.resolvers, parallelBestResolverCount)
						res1 := resolvers[0].resolver.(*UpstreamResolver)
						res2 := resolvers[1].resolver.(*UpstreamResolver)
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
			b := newTestBootstrap(ctx, &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

			r, err := NewParallelBestResolver(config.UpstreamGroup{
				Name:      "test",
				Upstreams: []config.Upstream{{Host: "example.com"}},
			}, b, verifyUpstreams)

			Expect(err).ShouldNot(Succeed())
			Expect(r).Should(BeNil())
		})
	})

	Describe("random resolver strategy", func() {
		const timeout = config.Duration(time.Second)

		BeforeEach(func() {
			config.GetConfig().Upstreams.Strategy = config.UpstreamStrategyRandom
			config.GetConfig().Upstreams.Timeout = timeout
		})

		Describe("Name", func() {
			It("should contain correct resolver", func() {
				Expect(sut.Name()).ShouldNot(BeEmpty())
				Expect(sut.Name()).Should(ContainSubstring(parallelResolverType))
			})
		})

		Describe("Resolving request in random order", func() {
			When("Multiple upstream resolvers are defined", func() {
				When("Both are responding", func() {
					When("Both respond in time", func() {
						BeforeEach(func() {
							testUpstream1 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
							DeferCleanup(testUpstream1.Close)

							testUpstream2 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.123")
							DeferCleanup(testUpstream2.Close)

							upstreams = []config.Upstream{testUpstream1.Start(), testUpstream2.Start()}
						})
						It("Should return result from either one", func() {
							request := newRequest("example.com.", A)
							Expect(sut.Resolve(request)).
								Should(SatisfyAll(
									HaveTTL(BeNumerically("==", 123)),
									HaveResponseType(ResponseTypeRESOLVED),
									HaveReturnCode(dns.RcodeSuccess),
									Or(
										BeDNSRecord("example.com.", A, "123.124.122.122"),
										BeDNSRecord("example.com.", A, "123.124.122.123"),
									),
								))
						})
					})
					When("one upstream exceeds timeout", func() {
						BeforeEach(func() {
							testUpstream1 := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
								response, err := util.NewMsgWithAnswer("example.com", 123, A, "123.124.122.1")
								time.Sleep(time.Duration(timeout) + 2*time.Second)

								Expect(err).To(Succeed())

								return response
							})
							DeferCleanup(testUpstream1.Close)

							testUpstream2 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.2")
							DeferCleanup(testUpstream2.Close)

							upstreams = []config.Upstream{testUpstream1.Start(), testUpstream2.Start()}
						})
						It("should ask a other random upstream and return its response", func() {
							request := newRequest("example.com", A)
							Expect(sut.Resolve(request)).Should(
								SatisfyAll(
									BeDNSRecord("example.com.", A, "123.124.122.2"),
									HaveTTL(BeNumerically("==", 123)),
									HaveResponseType(ResponseTypeRESOLVED),
									HaveReturnCode(dns.RcodeSuccess),
								))
						})
					})
					When("two upstreams exceed timeout", func() {
						BeforeEach(func() {
							testUpstream1 := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
								response, err := util.NewMsgWithAnswer("example.com", 123, A, "123.124.122.1")
								time.Sleep(timeout.ToDuration() + 2*time.Second)

								Expect(err).To(Succeed())

								return response
							})
							DeferCleanup(testUpstream1.Close)

							testUpstream2 := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
								response, err := util.NewMsgWithAnswer("example.com", 123, A, "123.124.122.2")
								time.Sleep(timeout.ToDuration() + 2*time.Second)

								Expect(err).To(Succeed())

								return response
							})
							DeferCleanup(testUpstream2.Close)

							testUpstream3 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.3")
							DeferCleanup(testUpstream3.Close)

							upstreams = []config.Upstream{testUpstream1.Start(), testUpstream2.Start(), testUpstream3.Start()}
						})
						// These two tests are flaky -_- (maybe recreate the RandomResolver )
						It("should not return error (due to random selection the request could to through)", func() {
							Eventually(func() error {
								request := newRequest("example.com", A)
								_, err := sut.Resolve(request)

								return err
							}).WithTimeout(30 * time.Second).
								Should(Not(HaveOccurred()))
						})
						It("should return error (because it can be possible that the two broken upstreams are chosen)", func() {
							Eventually(func() error {
								sutConfig := config.UpstreamGroup{
									Name:      upstreamDefaultCfgName,
									Upstreams: upstreams,
								}
								sut, err = NewParallelBestResolver(sutConfig, bootstrap, sutVerify)

								request := newRequest("example.com", A)
								_, err := sut.Resolve(request)

								return err
							}).WithTimeout(30 * time.Second).
								Should(HaveOccurred())
						})
					})
				})
				When("None are working", func() {
					BeforeEach(func() {
						testUpstream1 := config.Upstream{Host: "wrong"}
						testUpstream2 := config.Upstream{Host: "wrong"}

						upstreams = []config.Upstream{testUpstream1, testUpstream2}
						Expect(err).Should(Succeed())
					})
					It("Should return error", func() {
						request := newRequest("example.com.", A)
						_, err := sut.Resolve(request)
						Expect(err).Should(HaveOccurred())
					})
				})
			})
			When("only 1 upstream resolvers is defined", func() {
				BeforeEach(func() {
					mockUpstream := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
					DeferCleanup(mockUpstream.Close)

					upstreams = []config.Upstream{mockUpstream.Start()}
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
			When("4 upstream resolvers are defined", func() {
				It("should use 2 random peeked resolvers, weighted with last error timestamp", func() {
					withError1 := config.Upstream{Host: "wrong1"}
					withError2 := config.Upstream{Host: "wrong2"}

					mockUpstream1 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
					DeferCleanup(mockUpstream1.Close)

					mockUpstream2 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
					DeferCleanup(mockUpstream2.Close)

					sut, _ = NewParallelBestResolver(config.UpstreamGroup{
						Name:      upstreamDefaultCfgName,
						Upstreams: []config.Upstream{withError1, mockUpstream1.Start(), mockUpstream2.Start(), withError2},
					},
						systemResolverBootstrap, noVerifyUpstreams)

					By("all resolvers have same weight for random -> equal distribution", func() {
						resolverCount := make(map[Resolver]int)

						for i := 0; i < 2000; i++ {
							r := weightedRandom(sut.resolvers, nil)
							resolverCount[r.resolver]++
						}
						for _, v := range resolverCount {
							// should be 500 ± 100
							Expect(v).Should(BeNumerically("~", 500, 100))
						}
					})
					By("perform 100 request, error upstream's weight will be reduced", func() {
						for i := 0; i < 100; i++ {
							request := newRequest("example.com.", A)
							_, _ = sut.Resolve(request)
						}
					})

					By("Resolvers without errors should be selected often", func() {
						resolverCount := make(map[*UpstreamResolver]int)

						for i := 0; i < 200; i++ {
							r := weightedRandom(sut.resolvers, nil)
							res := r.resolver.(*UpstreamResolver)

							resolverCount[res]++
						}
						for k, v := range resolverCount {
							if strings.Contains(k.String(), "wrong") {
								// error resolvers: should be 0 - 10
								Expect(v).Should(BeNumerically("~", 0, 10))
							} else {
								// should be 90 ± 10
								Expect(v).Should(BeNumerically("~", 95, 20))
							}
						}
					})
				})
			})
		})
	})
})
