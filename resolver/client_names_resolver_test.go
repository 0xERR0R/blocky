package resolver

import (
	"errors"
	"net"

	"github.com/0xERR0R/blocky/config"

	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("ClientResolver", Label("clientNamesResolver"), func() {
	var (
		sut       *ClientNamesResolver
		sutConfig config.ClientLookupConfig
		m         *MockResolver
	)

	JustBeforeEach(func() {
		res, err := NewClientNamesResolver(sutConfig, skipUpstreamCheck)
		Expect(err).Should(Succeed())
		sut = res
		m = &MockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("Resolve client name from request clientID", func() {
		BeforeEach(func() {
			sutConfig = config.ClientLookupConfig{}
		})
		AfterEach(func() {
			// next resolver will be called
			m.AssertExpectations(GinkgoT())
		})

		It("should use clientID if set", func() {
			request := newRequestWithClientID("google1.de.", dns.Type(dns.TypeA), "1.2.3.4", "client123")
			resp, err := sut.Resolve(request)
			Expect(err).Should(Succeed())

			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(request.ClientNames).Should(HaveLen(1))
			Expect(request.ClientNames[0]).Should(Equal("client123"))
		})
		It("should use IP as fallback if clientID not set", func() {
			request := newRequestWithClientID("google2.de.", dns.Type(dns.TypeA), "1.2.3.4", "")
			resp, err := sut.Resolve(request)
			Expect(err).Should(Succeed())

			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(request.ClientNames).Should(HaveLen(1))
			Expect(request.ClientNames[0]).Should(Equal("1.2.3.4"))
		})

	})
	Describe("Resolve client name with custom name mapping", Label("XXX"), func() {
		BeforeEach(func() {
			sutConfig = config.ClientLookupConfig{
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
			resp, err := sut.Resolve(request)
			Expect(err).Should(Succeed())

			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(request.ClientNames).Should(HaveLen(1))
			Expect(request.ClientNames[0]).Should(Equal("client7"))
		})

		It("should resolve defined name with ipv6 address", func() {
			request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "2a02:590:505:4700:2e4f:1503:ce74:df78")
			resp, err := sut.Resolve(request)
			Expect(err).Should(Succeed())

			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(request.ClientNames).Should(HaveLen(1))
			Expect(request.ClientNames[0]).Should(Equal("client7"))
		})
		It("should resolve multiple names defined names", func() {
			request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "1.2.3.5")
			resp, err := sut.Resolve(request)
			Expect(err).Should(Succeed())

			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(request.ClientNames).Should(HaveLen(2))
			Expect(request.ClientNames).Should(ContainElements("client7", "client8"))
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
					DeferCleanup(testUpstream.Close)
					sutConfig = config.ClientLookupConfig{
						Upstream: testUpstream.Start(),
					}

				})

				It("should resolve client name", func() {
					By("first request", func() {
						request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
						resp, err := sut.Resolve(request)
						Expect(err).Should(Succeed())

						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(request.ClientNames[0]).Should(Equal("host1"))
						Expect(testUpstream.GetCallCount()).Should(Equal(1))
					})

					By("second request", func() {
						request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
						resp, err := sut.Resolve(request)
						Expect(err).Should(Succeed())

						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(request.ClientNames[0]).Should(Equal("host1"))
						// use cache -> call count 1
						Expect(testUpstream.GetCallCount()).Should(Equal(1))
					})

					By("reset cache", func() {
						sut.FlushCache()
					})

					By("third request", func() {
						request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
						resp, err := sut.Resolve(request)
						Expect(err).Should(Succeed())

						// no cache -> call count 2
						Expect(testUpstream.GetCallCount()).Should(Equal(2))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(request.ClientNames[0]).Should(Equal("host1"))
					})

				})
			})

			When("Client has multiple names", func() {
				BeforeEach(func() {
					testUpstream = NewMockUDPUpstreamServer().
						WithAnswerRR("25.178.168.192.in-addr.arpa. 600 IN PTR myhost1", "25.178.168.192.in-addr.arpa. 600 IN PTR myhost2")
					DeferCleanup(testUpstream.Close)
					sutConfig = config.ClientLookupConfig{
						Upstream: testUpstream.Start(),
					}
				})

				It("should resolve all client names", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
					resp, err := sut.Resolve(request)
					Expect(err).Should(Succeed())

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(request.ClientNames).Should(HaveLen(2))
					Expect(request.ClientNames[0]).Should(Equal("myhost1"))
					Expect(request.ClientNames[1]).Should(Equal("myhost2"))
					Expect(testUpstream.GetCallCount()).Should(Equal(1))
				})
			})

		})
		Context("with order", func() {
			BeforeEach(func() {
				sutConfig = config.ClientLookupConfig{
					SingleNameOrder: []uint{2, 1},
				}

			})
			When("Client has one name", func() {
				BeforeEach(func() {
					testUpstream = NewMockUDPUpstreamServer().
						WithAnswerRR("25.178.168.192.in-addr.arpa. 600 IN PTR host1")
					DeferCleanup(testUpstream.Close)
					sutConfig.Upstream = testUpstream.Start()

				})

				It("should resolve client name", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
					resp, err := sut.Resolve(request)
					Expect(err).Should(Succeed())

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(request.ClientNames[0]).Should(Equal("host1"))
					Expect(testUpstream.GetCallCount()).Should(Equal(1))
				})
			})
			When("Client has multiple names", func() {
				BeforeEach(func() {
					testUpstream = NewMockUDPUpstreamServer().
						WithAnswerRR("25.178.168.192.in-addr.arpa. 600 IN PTR myhost1", "25.178.168.192.in-addr.arpa. 600 IN PTR myhost2")
					DeferCleanup(testUpstream.Close)
					sutConfig.Upstream = testUpstream.Start()
				})

				It("should resolve the client name depending to defined order", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
					resp, err := sut.Resolve(request)
					Expect(err).Should(Succeed())

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(request.ClientNames).Should(HaveLen(1))
					Expect(request.ClientNames[0]).Should(Equal("myhost2"))
					Expect(testUpstream.GetCallCount()).Should(Equal(1))
				})
			})
		})

		Context("Error cases", func() {
			When("Upstream can't resolve client name via rDNS", func() {
				BeforeEach(func() {
					testUpstream = NewMockUDPUpstreamServer().
						WithAnswerError(dns.RcodeNameError)
					DeferCleanup(testUpstream.Close)
					sutConfig = config.ClientLookupConfig{
						Upstream: testUpstream.Start(),
					}
				})

				It("should use fallback for client name", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
					resp, err := sut.Resolve(request)
					Expect(err).Should(Succeed())

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(request.ClientNames).Should(HaveLen(1))
					Expect(request.ClientNames[0]).Should(Equal("192.168.178.25"))
					Expect(testUpstream.GetCallCount()).Should(Equal(1))
				})
			})
			When("Upstream produces error", func() {
				BeforeEach(func() {
					sutConfig = config.ClientLookupConfig{}
					clientMockResolver := &MockResolver{}
					clientMockResolver.On("Resolve", mock.Anything).Return(nil, errors.New("error"))
					sut.externalResolver = clientMockResolver
				})
				It("should use fallback for client name", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
					resp, err := sut.Resolve(request)
					Expect(err).Should(Succeed())

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(request.ClientNames).Should(HaveLen(1))
					Expect(request.ClientNames[0]).Should(Equal("192.168.178.25"))
				})
			})

			When("Client has no IP", func() {
				BeforeEach(func() {
					sutConfig = config.ClientLookupConfig{}
				})
				It("should resolve no names", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "")
					resp, err := sut.Resolve(request)
					Expect(err).Should(Succeed())

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(request.ClientNames).Should(BeEmpty())
				})
			})

			When("No upstream is defined", func() {
				BeforeEach(func() {
					sutConfig = config.ClientLookupConfig{}
				})
				It("should use fallback for client name", func() {
					request := newRequestWithClient("google.de.", dns.Type(dns.TypeA), "192.168.178.25")
					resp, err := sut.Resolve(request)
					Expect(err).Should(Succeed())

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(request.ClientNames).Should(HaveLen(1))
					Expect(request.ClientNames[0]).Should(Equal("192.168.178.25"))
				})
			})
		})
	})
	Describe("Connstruction", func() {
		When("upstream is invalid", func() {
			It("errors during construction", func() {
				b := TestBootstrap(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

				r, err := NewClientNamesResolver(config.ClientLookupConfig{
					Upstream: config.Upstream{Host: "example.com"},
				}, b)

				Expect(err).ShouldNot(Succeed())
				Expect(r).Should(BeNil())
			})
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			BeforeEach(func() {
				sutConfig = config.ClientLookupConfig{
					Upstream:        config.Upstream{Net: config.NetProtocolTcpUdp, Host: "host"},
					SingleNameOrder: []uint{1, 2},
					ClientnameIPMapping: map[string][]net.IP{
						"client8": {net.ParseIP("1.2.3.5")},
					},
				}
			})
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(len(c)).Should(BeNumerically(">", 1))
			})
		})

		When("resolver is disabled", func() {
			BeforeEach(func() {
				sutConfig = config.ClientLookupConfig{}
			})
			It("should return 'deactivated'", func() {
				c := sut.Configuration()
				Expect(c).Should(HaveLen(1))
				Expect(c).Should(Equal([]string{"deactivated, use only IP address"}))
			})
		})

	})
})
