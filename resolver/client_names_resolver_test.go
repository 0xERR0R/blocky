package resolver

import (
	"context"
	"errors"
	"net"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"

	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("ClientResolver", Label("clientNamesResolver"), func() {
	var (
		sut       *ClientNamesResolver
		sutConfig config.ClientLookup
		m         *mockResolver

		ctx      context.Context
		cancelFn context.CancelFunc
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	JustBeforeEach(func() {
		var err error

		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		sut, err = NewClientNamesResolver(ctx, sutConfig, defaultUpstreamsConfig, nil)
		Expect(err).Should(Succeed())
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
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

	Describe("Resolve client name from request clientID", func() {
		BeforeEach(func() {
			sutConfig = config.ClientLookup{}
		})
		AfterEach(func() {
			// next resolver will be called
			m.AssertExpectations(GinkgoT())
		})

		It("should use clientID if set", func() {
			request := newRequestWithClientID("google1.de.", dns.Type(dns.TypeA), "1.2.3.4", "client123")
			Expect(sut.Resolve(ctx, request)).
				Should(
					SatisfyAll(
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			Expect(request.ClientNames).Should(ConsistOf("client123"))
		})
		It("should use IP as fallback if clientID not set", func() {
			request := newRequestWithClientID("google2.de.", dns.Type(dns.TypeA), "1.2.3.4", "")
			Expect(sut.Resolve(ctx, request)).
				Should(
					SatisfyAll(
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			Expect(request.ClientNames).Should(ConsistOf("1.2.3.4"))
		})
	})
	Describe("Resolve client name with custom name mapping", Label("XXX"), func() {
		BeforeEach(func() {
			sutConfig = config.ClientLookup{
				ClientnameIPMapping: map[string][]net.IP{
					"client7": {
						net.ParseIP("1.2.3.4"), net.ParseIP("1.2.3.5"), net.ParseIP("2a02:590:505:4700:2e4f:1503:ce74:df78"),
					},
					"client8": {
						net.ParseIP("1.2.3.5"),
					},
				},
			}
		})
		AfterEach(func() {
			// next resolver will be called
			m.AssertExpectations(GinkgoT())
		})

		It("should resolve defined name with ipv4 address", func() {
			request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "1.2.3.4")
			Expect(sut.Resolve(ctx, request)).
				Should(
					SatisfyAll(
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			Expect(request.ClientNames).Should(ConsistOf("client7"))
		})

		It("should resolve defined name with ipv6 address", func() {
			request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "2a02:590:505:4700:2e4f:1503:ce74:df78")
			Expect(sut.Resolve(ctx, request)).
				Should(
					SatisfyAll(
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			Expect(request.ClientNames).Should(ConsistOf("client7"))
		})
		It("should resolve multiple names defined names", func() {
			request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "1.2.3.5")
			Expect(sut.Resolve(ctx, request)).
				Should(
					SatisfyAll(
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			Expect(request.ClientNames).Should(ConsistOf("client7", "client8"))
		})
	})

	Describe("Resolve client name via rDNS lookup", func() {
		var testUpstream *MockUDPUpstreamServer

		AfterEach(func() {
			// next resolver will be called
			m.AssertExpectations(GinkgoT())
		})

		Context("Without order", func() {
			When("Client has one name", func() {
				BeforeEach(func() {
					testUpstream = NewMockUDPUpstreamServer().
						WithAnswerRR("25.178.168.192.in-addr.arpa. 600 IN PTR host1")

					sutConfig = config.ClientLookup{
						Upstream: testUpstream.Start(),
					}
				})

				JustBeforeEach(func() {
					// Don't count the resolver test
					testUpstream.ResetCallCount()
				})

				It("should resolve client name", func() {
					By("first request", func() {
						request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
						Expect(sut.Resolve(ctx, request)).
							Should(
								SatisfyAll(
									HaveResponseType(ResponseTypeRESOLVED),
									HaveReturnCode(dns.RcodeSuccess),
								))

						Expect(request.ClientNames).Should(ConsistOf("host1"))
					})

					By("second request", func() {
						request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
						Expect(sut.Resolve(ctx, request)).
							Should(
								SatisfyAll(
									HaveResponseType(ResponseTypeRESOLVED),
									HaveReturnCode(dns.RcodeSuccess),
								))

						Expect(request.ClientNames).Should(ConsistOf("host1"))
						// use cache -> call count 1
						Expect(testUpstream.GetCallCount()).Should(Equal(1))
					})

					By("reset cache", func() {
						sut.FlushCache()
					})

					By("third request", func() {
						request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
						Expect(sut.Resolve(ctx, request)).
							Should(
								SatisfyAll(
									HaveResponseType(ResponseTypeRESOLVED),
									HaveReturnCode(dns.RcodeSuccess),
								))

						// no cache -> call count 2
						Expect(request.ClientNames).Should(ConsistOf("host1"))
						Expect(testUpstream.GetCallCount()).Should(Equal(2))
					})
				})
			})

			When("Client has multiple names", func() {
				BeforeEach(func() {
					testUpstream = NewMockUDPUpstreamServer().
						WithAnswerRR("25.178.168.192.in-addr.arpa. 600 IN PTR myhost1", "25.178.168.192.in-addr.arpa. 600 IN PTR myhost2")

					sutConfig = config.ClientLookup{
						Upstream: testUpstream.Start(),
					}
				})

				JustBeforeEach(func() {
					// Don't count the resolver test
					testUpstream.ResetCallCount()
				})

				It("should resolve all client names", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
					Expect(sut.Resolve(ctx, request)).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					Expect(request.ClientNames).Should(ConsistOf("myhost1", "myhost2"))
					Expect(testUpstream.GetCallCount()).Should(Equal(1))
				})
			})
		})
		Context("with order", func() {
			BeforeEach(func() {
				sutConfig = config.ClientLookup{
					SingleNameOrder: []uint{2, 1},
				}
			})
			When("Client has one name", func() {
				BeforeEach(func() {
					testUpstream = NewMockUDPUpstreamServer().
						WithAnswerRR("25.178.168.192.in-addr.arpa. 600 IN PTR host1")

					sutConfig.Upstream = testUpstream.Start()
				})

				JustBeforeEach(func() {
					// Don't count the resolver test
					testUpstream.ResetCallCount()
				})

				It("should resolve client name", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
					Expect(sut.Resolve(ctx, request)).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					Expect(request.ClientNames).Should(ConsistOf("host1"))
					Expect(testUpstream.GetCallCount()).Should(Equal(1))
				})
			})
			When("Client has multiple names", func() {
				BeforeEach(func() {
					testUpstream = NewMockUDPUpstreamServer().
						WithAnswerRR("25.178.168.192.in-addr.arpa. 600 IN PTR myhost1", "25.178.168.192.in-addr.arpa. 600 IN PTR myhost2")

					sutConfig.Upstream = testUpstream.Start()
				})

				JustBeforeEach(func() {
					// Don't count the resolver test
					testUpstream.ResetCallCount()
				})

				It("should resolve the client name depending to defined order", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
					Expect(sut.Resolve(ctx, request)).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					Expect(request.ClientNames).Should(ConsistOf("myhost2"))
					Expect(testUpstream.GetCallCount()).Should(Equal(1))
				})
			})
		})

		Context("Error cases", func() {
			When("Upstream can't resolve client name via rDNS", func() {
				BeforeEach(func() {
					testUpstream = NewMockUDPUpstreamServer().
						WithAnswerError(dns.RcodeNameError)

					sutConfig = config.ClientLookup{
						Upstream: testUpstream.Start(),
					}
				})

				JustBeforeEach(func() {
					// Don't count the resolver test
					testUpstream.ResetCallCount()
				})

				It("should use fallback for client name", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
					Expect(sut.Resolve(ctx, request)).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					Expect(request.ClientNames).Should(ConsistOf("192.168.178.25"))
					Expect(testUpstream.GetCallCount()).Should(Equal(1))
				})
			})
			When("Upstream produces error", func() {
				JustBeforeEach(func() {
					sutConfig = config.ClientLookup{}
					clientMockResolver := &mockResolver{}
					clientMockResolver.On("Resolve", mock.Anything).Return(nil, errors.New("error"))
					sut.externalResolver = clientMockResolver
				})
				It("should use fallback for client name", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
					Expect(sut.Resolve(ctx, request)).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					Expect(request.ClientNames).Should(ConsistOf("192.168.178.25"))
				})
			})

			When("Client has no IP", func() {
				BeforeEach(func() {
					sutConfig = config.ClientLookup{}
				})
				It("should resolve no names", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "")
					Expect(sut.Resolve(ctx, request)).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
					Expect(request.ClientNames).Should(BeEmpty())
				})
			})

			When("No upstream is defined", func() {
				BeforeEach(func() {
					sutConfig = config.ClientLookup{}
				})
				It("should use fallback for client name", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
					Expect(sut.Resolve(ctx, request)).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					Expect(request.ClientNames).Should(ConsistOf("192.168.178.25"))
				})
			})
		})
	})
	Describe("Connstruction", func() {
		When("upstream is invalid", func() {
			It("errors during construction", func() {
				b := newTestBootstrap(ctx, &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

				upstreamsCfg := defaultUpstreamsConfig
				upstreamsCfg.Init.Strategy = config.InitStrategyFailOnError

				r, err := NewClientNamesResolver(ctx, config.ClientLookup{
					Upstream: config.Upstream{Host: "example.com"},
				}, upstreamsCfg, b)

				Expect(err).Should(HaveOccurred())
				Expect(r).Should(BeNil())
			})
		})
	})
})
