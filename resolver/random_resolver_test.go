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

var _ = Describe("RandomResolver", Label("randomResolver"), func() {
	const (
		verifyUpstreams   = true
		noVerifyUpstreams = false
	)

	var (
		sut       *RandomResolver
		upstreams []config.Upstream
		sutVerify bool

		err error

		bootstrap *Bootstrap
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		upstreams = []config.Upstream{
			{Host: "wrong"},
			{Host: "127.0.0.2"},
		}

		sutVerify = noVerifyUpstreams

		bootstrap = systemResolverBootstrap
	})

	JustBeforeEach(func() {
		sutConfig := config.UpstreamGroup{
			Name:      upstreamDefaultCfgName,
			Upstreams: upstreams,
		}
		sut, err = NewRandomResolver(sutConfig, bootstrap, sutVerify)
	})

	config.GetConfig().Upstreams.Timeout = config.Duration(1000 * time.Millisecond)

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
			Expect(sut.Name()).Should(ContainSubstring(randomResolverType))
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

			_, err := NewRandomResolver(config.UpstreamGroup{
				Name:      upstreamDefaultCfgName,
				Upstreams: upstreams,
			},
				systemResolverBootstrap, verifyUpstreams)
			Expect(err).Should(Not(HaveOccurred()))
		})
	})

	When("no upstream resolvers can be reached", func() {
		BeforeEach(func() {
			upstreams = []config.Upstream{
				{Host: "wrong"},
				{Host: "127.0.0.2"},
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
							time.Sleep(time.Duration(config.GetConfig().Upstreams.Timeout) + 2*time.Second)

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
							time.Sleep(config.GetConfig().Upstreams.Timeout.ToDuration() + 2*time.Second)

							Expect(err).To(Succeed())

							return response
						})
						DeferCleanup(testUpstream1.Close)

						testUpstream2 := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
							response, err := util.NewMsgWithAnswer("example.com", 123, A, "123.124.122.2")
							time.Sleep(config.GetConfig().Upstreams.Timeout.ToDuration() + 2*time.Second)

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
							sut, err = NewRandomResolver(sutConfig, bootstrap, sutVerify)

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

				sut, _ = NewRandomResolver(config.UpstreamGroup{
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
				By("perform 200 request, error upstream's weight will be reduced", func() {
					for i := 0; i < 200; i++ {
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
							// should be 100 ± 20
							Expect(v).Should(BeNumerically("~", 100, 20))
						}
					}
				})
			})
		})
	})
})
