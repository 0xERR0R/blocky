package resolver

import (
	"context"
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

var _ = Describe("StrictResolver", Label("strictResolver"), func() {
	var (
		sut             *StrictResolver
		sutInitStrategy config.InitStrategy
		upstreams       []config.Upstream

		err error

		bootstrap *Bootstrap

		ctx      context.Context
		cancelFn context.CancelFunc
		timeout  = 2 * time.Second

		testUpstream1 *MockUDPUpstreamServer
		testUpstream2 *MockUDPUpstreamServer
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		upstreams = []config.Upstream{
			{Host: "wrong"},
			{Host: "127.0.0.2"},
		}

		sutInitStrategy = config.InitStrategyBlocking

		bootstrap = systemResolverBootstrap
	})

	JustBeforeEach(func() {
		upstreamsCfg := defaultUpstreamsConfig
		upstreamsCfg.Init.Strategy = sutInitStrategy

		sutConfig := config.NewUpstreamGroup("test", upstreamsCfg, upstreams)
		sutConfig.Timeout = config.Duration(timeout)
		sut, err = NewStrictResolver(ctx, sutConfig, bootstrap)
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

	Describe("Type", func() {
		It("should be correct", func() {
			Expect(sut.Type()).ShouldNot(BeEmpty())
			Expect(sut.Type()).Should(Equal(strictResolverType))
		})
	})

	Describe("Name", func() {
		It("should contain correct resolver", func() {
			Expect(sut.Name()).ShouldNot(BeEmpty())
			Expect(sut.Name()).Should(ContainSubstring(strictResolverType))
		})
	})

	When("some default upstream resolvers cannot be reached", func() {
		BeforeEach(func() {
			mockUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
				response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 123, A, "123.124.122.122")

				return
			})

			upstreams = []config.Upstream{
				{Host: "wrong"},
				mockUpstream.Start(),
			}
		})

		It("should start normally", func() {
			Expect(err).Should(Succeed())
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
				sutInitStrategy = config.InitStrategyFailOnError
			})
			It("should fail to start", func() {
				Expect(err).Should(HaveOccurred())
			})
		})

		When("strict checking is disabled", func() {
			BeforeEach(func() {
				sutInitStrategy = config.InitStrategyBlocking
			})
			It("should start", func() {
				Expect(err).Should(Succeed())
			})
		})
	})

	Describe("Resolving request in strict order", func() {
		When("2 Upstream resolvers are defined", func() {
			When("Both are responding", func() {
				When("they respond in time", func() {
					BeforeEach(func() {
						testUpstream1 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
						testUpstream2 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.123")

						upstreams = []config.Upstream{testUpstream1.Start(), testUpstream2.Start()}
					})
					It("Should use result from first one", func() {
						request := newRequest("example.com.", A)
						Expect(sut.Resolve(ctx, request)).
							Should(
								SatisfyAll(
									BeDNSRecord("example.com.", A, "123.124.122.122"),
									HaveTTL(BeNumerically("==", 123)),
									HaveResponseType(ResponseTypeRESOLVED),
									HaveReturnCode(dns.RcodeSuccess),
								))
					})
				})
				When("first upstream times-out", func() {
					BeforeEach(func() {
						testUpstream1 = NewMockUDPUpstreamServer().
							WithAnswerRR("example.com 123 IN A 123.124.122.1").
							WithDelay(2 * timeout)

						testUpstream2 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.2")

						upstreams = []config.Upstream{testUpstream1.Start(), testUpstream2.Start()}
					})
					It("should return response from next upstream", func() {
						request := newRequest("example.com", A)
						Expect(sut.Resolve(ctx, request)).Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.2"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
					})
				})
				When("all upstreams timeout", func() {
					JustBeforeEach(func() {
						testUpstream1 = NewMockUDPUpstreamServer().
							WithAnswerRR("example.com 123 IN A 123.124.122.1").
							WithDelay(2 * timeout)

						testUpstream2 = NewMockUDPUpstreamServer().
							WithAnswerRR("example.com 123 IN A 123.124.122.2").
							WithDelay(2 * timeout)

						upstreams = []config.Upstream{testUpstream1.Start(), testUpstream2.Start()}
					})
					It("should return error", func() {
						request := newRequest("example.com", A)
						_, err := sut.Resolve(ctx, request)
						Expect(err).To(HaveOccurred())
					})
				})
			})
			When("Only second is working", func() {
				BeforeEach(func() {
					testUpstream2 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.123")

					upstreams = []config.Upstream{{Host: "wrong"}, testUpstream2.Start()}
				})
				It("Should use result from second one", func() {
					request := newRequest("example.com.", A)
					Expect(sut.Resolve(ctx, request)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.123"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
			})
			When("None are working", func() {
				BeforeEach(func() {
					upstreams = []config.Upstream{{Host: "wrong"}, {Host: "wrong"}}
					Expect(err).Should(Succeed())
				})
				It("Should return error", func() {
					request := newRequest("example.com.", A)
					_, err = sut.Resolve(ctx, request)
					Expect(err).Should(HaveOccurred())
				})
			})
		})
		When("only 1 upstream resolvers is defined", func() {
			BeforeEach(func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")

				upstreams = []config.Upstream{mockUpstream.Start()}
			})
			It("Should use result from defined resolver", func() {
				request := newRequest("example.com.", A)

				Expect(sut.Resolve(ctx, request)).
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
})
