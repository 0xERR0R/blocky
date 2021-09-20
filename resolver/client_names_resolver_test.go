package resolver

import (
	"errors"
	"fmt"
	"net"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"

	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("ClientResolver", func() {
	var (
		sut                          *ClientNamesResolver
		sutConfig                    config.ClientLookupConfig
		m                            *resolverMock
		mockReverseUpstream          config.Upstream
		mockReverseUpstreamCallCount int
		mockReverseUpstreamAnswer    *dns.Msg

		err  error
		resp *Response
	)

	BeforeEach(func() {
		mockReverseUpstreamAnswer = new(dns.Msg)
		mockReverseUpstreamCallCount = 0

		mockReverseUpstream = TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
			mockReverseUpstreamCallCount++
			Expect(err).Should(Succeed())

			return mockReverseUpstreamAnswer
		})
		sutConfig = config.ClientLookupConfig{
			Upstream: mockReverseUpstream,
		}

	})

	JustBeforeEach(func() {
		sut = NewClientNamesResolver(sutConfig).(*ClientNamesResolver)
		m = &resolverMock{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)

	})

	Describe("Resolve client name with custom name mapping", func() {
		BeforeEach(func() {
			sutConfig = config.ClientLookupConfig{
				Upstream: mockReverseUpstream,
				ClientnameIPMapping: map[string][]net.IP{
					"client7": {net.ParseIP("1.2.3.4"), net.ParseIP("1.2.3.5"), net.ParseIP("2a02:590:505:4700:2e4f:1503:ce74:df78")},
					"client8": {net.ParseIP("1.2.3.5")},
				},
			}
		})

		It("should resolve defined name with ipv4 address", func() {
			request := newRequestWithClient("google.de.", dns.TypeA, "1.2.3.4")
			resp, err = sut.Resolve(request)

			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(request.ClientNames).Should(HaveLen(1))
			Expect(request.ClientNames[0]).Should(Equal("client7"))
			Expect(mockReverseUpstreamCallCount).Should(Equal(0))
		})

		It("should resolve defined name with ipv6 address", func() {
			request := newRequestWithClient("google.de.", dns.TypeA, "2a02:590:505:4700:2e4f:1503:ce74:df78")
			resp, err = sut.Resolve(request)

			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(request.ClientNames).Should(HaveLen(1))
			Expect(request.ClientNames[0]).Should(Equal("client7"))
			Expect(mockReverseUpstreamCallCount).Should(Equal(0))
		})
		It("should resolve multiple names defined names", func() {
			request := newRequestWithClient("google.de.", dns.TypeA, "1.2.3.5")
			resp, err = sut.Resolve(request)

			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(request.ClientNames).Should(HaveLen(2))
			Expect(request.ClientNames).Should(ContainElements("client7", "client8"))
			Expect(mockReverseUpstreamCallCount).Should(Equal(0))
		})
	})

	Describe("Resolve client name via rDNS lookup", func() {
		AfterEach(func() {
			// next resolver will be called
			m.AssertExpectations(GinkgoT())
			Expect(err).Should(Succeed())
		})
		Context("Without order", func() {
			When("Client has one name", func() {
				BeforeEach(func() {
					r, _ := dns.ReverseAddr("192.168.178.25")
					mockReverseUpstreamAnswer, _ = util.NewMsgWithAnswer(r, 600, dns.TypePTR, "host1")
				})

				It("should resolve client name", func() {
					By("first request", func() {
						request := newRequestWithClient("google.de.", dns.TypeA, "192.168.178.25")
						resp, err = sut.Resolve(request)

						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(request.ClientNames[0]).Should(Equal("host1"))
						Expect(mockReverseUpstreamCallCount).Should(Equal(1))
					})

					By("second request", func() {
						request := newRequestWithClient("google.de.", dns.TypeA, "192.168.178.25")
						resp, err = sut.Resolve(request)

						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(request.ClientNames[0]).Should(Equal("host1"))
						// use cache -> call count 1
						Expect(mockReverseUpstreamCallCount).Should(Equal(1))
					})

					// reset cache
					sut.FlushCache()

					By("third request", func() {
						request := newRequestWithClient("google.de.", dns.TypeA, "192.168.178.25")
						resp, err = sut.Resolve(request)

						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(request.ClientNames[0]).Should(Equal("host1"))
						// no cache -> call count 2
						Expect(mockReverseUpstreamCallCount).Should(Equal(2))
					})

				})
			})

			When("Client has multiple names", func() {
				BeforeEach(func() {
					r, _ := dns.ReverseAddr("192.168.178.25")
					rr1, err := dns.NewRR(fmt.Sprintf("%s 300 IN PTR myhost1", r))
					Expect(err).Should(Succeed())
					rr2, err := dns.NewRR(fmt.Sprintf("%s 300 IN PTR myhost2", r))
					Expect(err).Should(Succeed())

					mockReverseUpstreamAnswer.Answer = []dns.RR{rr1, rr2}
				})

				It("should resolve all client names", func() {
					request := newRequestWithClient("google.de.", dns.TypeA, "192.168.178.25")
					resp, err = sut.Resolve(request)

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(request.ClientNames).Should(HaveLen(2))
					Expect(request.ClientNames[0]).Should(Equal("myhost1"))
					Expect(request.ClientNames[1]).Should(Equal("myhost2"))
					Expect(mockReverseUpstreamCallCount).Should(Equal(1))
				})
			})

		})
		Context("with order", func() {
			BeforeEach(func() {
				sutConfig = config.ClientLookupConfig{
					Upstream:        mockReverseUpstream,
					SingleNameOrder: []uint{2, 1}}
			})
			When("Client has one name", func() {
				BeforeEach(func() {
					r, _ := dns.ReverseAddr("192.168.178.25")
					mockReverseUpstreamAnswer, _ = util.NewMsgWithAnswer(r, 600, dns.TypePTR, "host1")
				})

				It("should resolve client name", func() {
					request := newRequestWithClient("google.de.", dns.TypeA, "192.168.178.25")
					resp, err = sut.Resolve(request)

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(request.ClientNames[0]).Should(Equal("host1"))
					Expect(mockReverseUpstreamCallCount).Should(Equal(1))
				})
			})
			When("Client has multiple names", func() {
				BeforeEach(func() {
					r, _ := dns.ReverseAddr("192.168.178.25")
					rr1, err := dns.NewRR(fmt.Sprintf("%s 300 IN PTR myhost1", r))
					Expect(err).Should(Succeed())
					rr2, err := dns.NewRR(fmt.Sprintf("%s 300 IN PTR myhost2", r))
					Expect(err).Should(Succeed())

					mockReverseUpstreamAnswer.Answer = []dns.RR{rr1, rr2}
				})

				It("should resolve the client name depending to defined order", func() {
					request := newRequestWithClient("google.de.", dns.TypeA, "192.168.178.25")
					resp, err = sut.Resolve(request)

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(request.ClientNames).Should(HaveLen(1))
					Expect(request.ClientNames[0]).Should(Equal("myhost2"))
					Expect(mockReverseUpstreamCallCount).Should(Equal(1))
				})
			})
		})

		When("Upstream can't resolve client name via rDNS", func() {
			BeforeEach(func() {
				mockReverseUpstreamAnswer.Rcode = dns.RcodeNameError
			})
			It("should use fallback for client name", func() {
				request := newRequestWithClient("google.de.", dns.TypeA, "192.168.178.25")
				resp, err = sut.Resolve(request)

				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(request.ClientNames).Should(HaveLen(1))
				Expect(request.ClientNames[0]).Should(Equal("192.168.178.25"))
				Expect(mockReverseUpstreamCallCount).Should(Equal(1))
			})
		})
		When("Upstream produces error", func() {
			JustBeforeEach(func() {
				clientResolverMock := &resolverMock{}
				clientResolverMock.On("Resolve", mock.Anything).Return(nil, errors.New("error"))
				sut.externalResolver = clientResolverMock
			})
			It("should use fallback for client name", func() {
				request := newRequestWithClient("google.de.", dns.TypeA, "192.168.178.25")
				resp, err = sut.Resolve(request)

				Expect(request.ClientNames).Should(HaveLen(1))
				Expect(request.ClientNames[0]).Should(Equal("192.168.178.25"))
				Expect(mockReverseUpstreamCallCount).Should(Equal(0))
			})
		})

		When("Client has no IP", func() {
			It("should resolve no names", func() {
				request := newRequestWithClient("google.de.", dns.TypeA, "")
				resp, err = sut.Resolve(request)

				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(request.ClientNames).Should(BeEmpty())
				Expect(mockReverseUpstreamCallCount).Should(Equal(0))
			})
		})

		When("No upstream is defined", func() {
			BeforeEach(func() {
				sutConfig = config.ClientLookupConfig{}
			})
			It("should use fallback for client name", func() {
				request := newRequestWithClient("google.de.", dns.TypeA, "192.168.178.25")
				resp, err = sut.Resolve(request)

				Expect(request.ClientNames).Should(HaveLen(1))
				Expect(request.ClientNames[0]).Should(Equal("192.168.178.25"))
				Expect(mockReverseUpstreamCallCount).Should(Equal(0))
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
				Expect(len(c) > 1).Should(BeTrue())
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
