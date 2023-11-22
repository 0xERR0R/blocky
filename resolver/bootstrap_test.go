package resolver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Bootstrap", Label("bootstrap"), func() {
	var (
		sut       *Bootstrap
		sutConfig *config.Config
		ctx       context.Context
		cancelFn  context.CancelFunc

		err error
	)

	BeforeEach(func() {
		sutConfig = &config.Config{
			BootstrapDNS: []config.BootstrappedUpstreamConfig{
				{
					Upstream: config.Upstream{
						Net:  config.NetProtocolTcpTls,
						Host: "bootstrapUpstream.invalid",
					},
					IPs: []net.IP{net.IPv4zero},
				},
			},
			Upstreams: defaultUpstreamsConfig,
		}

		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)
	})

	JustBeforeEach(func() {
		sut, err = NewBootstrap(ctx, sutConfig)
		Expect(err).Should(Succeed())
	})

	Describe("configuration", func() {
		When("is not specified", func() {
			BeforeEach(func() {
				sutConfig = &config.Config{}
			})

			It("should use the system resolver", func() {
				usedSystemResolver := make(chan bool, 100)

				sut.systemResolver = &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						usedSystemResolver <- true

						return nil, errors.New("don't actually do anything")
					},
				}

				_, err := sut.resolveUpstream(ctx, nil, "example.com")
				Expect(err).ShouldNot(Succeed())
				Expect(usedSystemResolver).Should(Receive(BeTrue()))
			})

			Describe("HTTP transport", func() {
				It("should use the system resolver", func() {
					transport := sut.NewHTTPTransport()

					Expect(transport).ShouldNot(BeNil())
				})
			})

			When("one of multiple upstreams is invalid", func() {
				It("errors", func() {
					cfg := config.Config{
						BootstrapDNS: []config.BootstrappedUpstreamConfig{
							{
								Upstream: config.Upstream{ // valid
									Net:  config.NetProtocolTcpUdp,
									Host: "0.0.0.0",
								},
							},
							{
								Upstream: config.Upstream{ // invalid
									Net:  config.NetProtocolTcpUdp,
									Host: "hostname",
								},
							},
						},
					}

					_, err := NewBootstrap(ctx, &cfg)
					Expect(err).ShouldNot(Succeed())
				})
			})
		})

		Context("using TCP UDP", func() {
			When("hostname is an IP", func() {
				BeforeEach(func() {
					sutConfig = &config.Config{
						BootstrapDNS: []config.BootstrappedUpstreamConfig{
							{
								Upstream: config.Upstream{
									Net:  config.NetProtocolTcpUdp,
									Host: "0.0.0.0",
								},
							},
						},
					}
				})
				It("uses it", func() {
					Expect(sut).ShouldNot(BeNil())

					for _, ips := range sut.bootstraped {
						Expect(ips).Should(Equal([]net.IP{net.IPv4zero}))
					}
				})
			})

			When("using non IP hostname", func() {
				It("errors", func() {
					cfg := config.Config{
						BootstrapDNS: []config.BootstrappedUpstreamConfig{
							{
								Upstream: config.Upstream{
									Net:  config.NetProtocolTcpUdp,
									Host: "bootstrapUpstream.invalid",
								},
							},
						},
					}

					_, err := NewBootstrap(ctx, &cfg)
					Expect(err).ShouldNot(Succeed())
					Expect(err.Error()).Should(ContainSubstring("must use IP instead of hostname"))
				})
			})

			When("extra IPs are configured", func() {
				BeforeEach(func() {
					sutConfig = &config.Config{
						BootstrapDNS: []config.BootstrappedUpstreamConfig{
							{
								Upstream: config.Upstream{
									Net:  config.NetProtocolTcpUdp,
									Host: "0.0.0.0",
								},
								IPs: []net.IP{net.IPv4allrouter},
							},
						},
					}
				})
				It("uses them", func() {
					Expect(sut).ShouldNot(BeNil())

					for _, ips := range sut.bootstraped {
						Expect(ips).Should(ContainElements(net.IPv4zero, net.IPv4allrouter))
					}
				})
			})
		})

		Context("using encrypted DNS", func() {
			When("IPs are missing", func() {
				It("errors", func() {
					cfg := config.Config{
						BootstrapDNS: []config.BootstrappedUpstreamConfig{
							{
								Upstream: config.Upstream{
									Net:  config.NetProtocolTcpTls,
									Host: "bootstrapUpstream.invalid",
								},
							},
						},
					}

					_, err := NewBootstrap(ctx, &cfg)
					Expect(err).ShouldNot(Succeed())
					Expect(err.Error()).Should(ContainSubstring("no IPs configured"))
				})
			})

			When("hostname is IP", func() {
				It("doesn't require extra IPs", func() {
					cfg := config.Config{
						BootstrapDNS: []config.BootstrappedUpstreamConfig{
							{
								Upstream: config.Upstream{
									Net:  config.NetProtocolTcpTls,
									Host: "0.0.0.0",
								},
							},
						},
					}

					_, err := NewBootstrap(ctx, &cfg)
					Expect(err).Should(Succeed())
				})
			})
		})
	})

	Describe("resolving", func() {
		var bootstrapUpstream *mockResolver

		BeforeEach(func() {
			bootstrapUpstream = &mockResolver{}

			sutConfig.BootstrapDNS = []config.BootstrappedUpstreamConfig{
				{
					Upstream: config.Upstream{
						Net:  config.NetProtocolTcpTls,
						Host: "bootstrapUpstream.invalid",
					},
					IPs: []net.IP{net.IPv4zero},
				},
			}
		})

		JustBeforeEach(func() {
			sut.resolver = bootstrapUpstream
			sut.bootstraped = bootstrapedResolvers{bootstrapUpstream: sutConfig.BootstrapDNS[0].IPs}
		})

		AfterEach(func() {
			bootstrapUpstream.AssertExpectations(GinkgoT())
		})

		When("called from bootstrap.upstream", func() {
			It("uses hardcoded IPs", func() {
				ips, err := sut.resolveUpstream(ctx, bootstrapUpstream, "host")

				Expect(err).Should(Succeed())
				Expect(ips).Should(Equal(sutConfig.BootstrapDNS[0].IPs))
			})
		})

		When("hostname is an IP", func() {
			It("returns immediately", func() {
				ips, err := sut.resolve(ctx, "0.0.0.0", config.IPVersionDual.QTypes())

				Expect(err).Should(Succeed())
				Expect(ips).Should(ContainElement(net.IPv4zero))
			})
		})

		When("upstream returns an IPv6", func() {
			It("it is used", func() {
				bootstrapResponse, err := util.NewMsgWithAnswer(
					"localhost.", 123, AAAA, net.IPv6loopback.String(),
				)
				Expect(err).Should(Succeed())

				bootstrapUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: bootstrapResponse}, nil)

				ips, err := sut.resolve(ctx, "localhost", []dns.Type{AAAA})

				Expect(err).Should(Succeed())
				Expect(ips).Should(HaveLen(1))
				Expect(ips).Should(ContainElement(net.IPv6loopback))
			})
		})

		When("upstream returns an error", func() {
			It("it is returned", func() {
				resolveErr := errors.New("test")

				bootstrapUpstream.On("Resolve", mock.Anything).Return(nil, resolveErr)

				ips, err := sut.resolve(ctx, "localhost", []dns.Type{A})

				Expect(err).ShouldNot(Succeed())
				Expect(err.Error()).Should(ContainSubstring(resolveErr.Error()))
				Expect(ips).Should(BeEmpty())
			})
		})

		When("upstream returns an error response", func() {
			It("an error is returned", func() {
				bootstrapResponse := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}

				bootstrapUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: bootstrapResponse}, nil)

				ips, err := sut.resolve(ctx, "unknownhost.invalid", []dns.Type{A})

				Expect(err).ShouldNot(Succeed())
				Expect(err.Error()).Should(ContainSubstring("no such host"))
				Expect(ips).Should(BeEmpty())
			})
		})

		When("called from another UpstreamResolver", func() {
			It("uses the bootstrap upstream", func() {
				mainReq := &model.Request{
					Req: util.NewMsgWithQuestion("example.com.", A),
					Log: logrus.NewEntry(log.Log()),
				}

				mockUpstreamServer := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				DeferCleanup(mockUpstreamServer.Close)
				upstream := mockUpstreamServer.Start()

				upstreamIP := upstream.Host

				bootstrapResponse, err := util.NewMsgWithAnswer(
					"localhost.", 123, A, upstreamIP,
				)
				Expect(err).Should(Succeed())

				bootstrapUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: bootstrapResponse}, nil)

				upstream.Host = "localhost" // force bootstrap to do resolve, and not just return the IP as is

				r := newUpstreamResolverUnchecked(newUpstreamConfig(upstream, sutConfig.Upstreams), sut)

				rsp, err := r.Resolve(ctx, mainReq)
				Expect(err).Should(Succeed())
				Expect(mockUpstreamServer.GetCallCount()).Should(Equal(1))
				Expect(rsp.Res.Question[0].Name).Should(Equal("example.com."))
				Expect(rsp.Res.Id).ShouldNot(Equal(bootstrapResponse.Id))
			})
		})

		Describe("HTTP Transport", func() {
			It("uses the bootstrap upstream", func() {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				DeferCleanup(server.Close)

				url, err := url.Parse(server.URL)
				Expect(err).Should(Succeed())

				host, port, err := net.SplitHostPort(url.Host)
				Expect(err).Should(Succeed())

				bootstrapResponse, err := util.NewMsgWithAnswer(
					"localhost.", 123, A, host,
				)
				Expect(err).Should(Succeed())

				bootstrapUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: bootstrapResponse}, nil)

				// force bootstrap to do resolve, and not just return the IP as is
				url.Host = net.JoinHostPort("localhost", port)

				c := http.Client{
					Transport: sut.NewHTTPTransport(),
				}

				_, err = c.Get(url.String())
				Expect(err).Should(Succeed())
			})

			It("should error with malformed address", func() {
				t := sut.NewHTTPTransport()

				// implicit expectation of 0 bootstrapUpstream.Resolve calls

				_, err = t.DialContext(ctx, "ip", "!bad-addr!")
				Expect(err).ShouldNot(Succeed())
			})

			It("returns upstream errors", func() {
				resolveErr := errors.New("test")

				bootstrapUpstream.On("Resolve", mock.Anything).Return(nil, resolveErr)

				t := sut.NewHTTPTransport()

				_, err = t.DialContext(ctx, "ip", "abc:123")

				Expect(err).ShouldNot(Succeed())
				Expect(err.Error()).Should(ContainSubstring(resolveErr.Error()))
			})

			It("errors for unknown host", func() {
				bootstrapResponse := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}

				bootstrapUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: bootstrapResponse}, nil)

				t := sut.NewHTTPTransport()

				_, err = t.DialContext(ctx, "ip", "abc:123")

				Expect(err).ShouldNot(Succeed())
				Expect(err.Error()).Should(ContainSubstring("no such host"))
			})
		})
	})

	Describe("connectIPVersion", func() {
		var (
			m             *mockResolver
			dialIPVersion config.IPVersion
		)

		BeforeEach(func() {
			dialIPVersion = config.IPVersionDual
		})

		JustBeforeEach(func() {
			m = &mockResolver{AnswerFn: autoAnswer}
			sut.resolver = m

			m.On("Resolve", mock.Anything).
				Times(len(sutConfig.ConnectIPVersion.QTypes())).
				Run(func(args mock.Arguments) {
					req, ok := args.Get(0).(*model.Request)
					Expect(ok).Should(BeTrue())

					qType := dns.Type(req.Req.Question[0].Qtype)

					if sutConfig.ConnectIPVersion != config.IPVersionDual {
						Expect(qType).Should(BeElementOf(sutConfig.ConnectIPVersion.QTypes()))
					} else {
						Expect(qType).Should(BeElementOf(dialIPVersion.QTypes()))
					}
				})
		})

		Describe("resolve", func() {
			AfterEach(func() {
				_, err := sut.resolveUpstream(ctx, nil, "example.com")
				Expect(err).Should(Succeed())

				m.AssertExpectations(GinkgoT())
			})

			Context("using dual", func() {
				BeforeEach(func() {
					sutConfig.ConnectIPVersion = config.IPVersionV4
				})

				It("should query both IPv4 and IPv6", func() {})
			})

			Context("using v4", func() {
				BeforeEach(func() {
					sutConfig.ConnectIPVersion = config.IPVersionV4
				})

				It("should query IPv4 only", func() {})
			})

			Context("using v6", func() {
				BeforeEach(func() {
					sutConfig.ConnectIPVersion = config.IPVersionV6
				})

				It("should query IPv6 only", func() {})
			})
		})

		Describe("HTTP Transport", func() {
			var (
				d *mockDialer

				validIPs []string
			)

			JustBeforeEach(func() {
				d = newMockDialer()
				sut.dialer = d

				m.On("Resolve", mock.Anything).Once()

				d.On("DialContext", mock.Anything, mock.Anything, mock.Anything).
					Once().
					Run(func(args mock.Arguments) {
						network, ok := args.Get(1).(string)
						Expect(ok).Should(BeTrue())
						Expect(network).Should(Equal(dialIPVersion.Net()))

						addr, ok := args.Get(2).(string)
						Expect(ok).Should(BeTrue())

						ip, port, err := net.SplitHostPort(addr)
						Expect(err).Should(Succeed())
						Expect(ip).Should(BeElementOf(validIPs))
						Expect(port).Should(Equal("0"))
					})
			})

			AfterEach(func() {
				t := sut.NewHTTPTransport()

				conn, err := t.DialContext(ctx, dialIPVersion.Net(), "localhost:0")
				Expect(err).Should(Succeed())
				Expect(conn).Should(Equal(aMockConn))

				d.AssertExpectations(GinkgoT())
			})

			Context("using dual", func() {
				BeforeEach(func() {
					sutConfig.ConnectIPVersion = config.IPVersionDual
					validIPs = []string{autoAnswerIPv4.String(), autoAnswerIPv6.String()}
				})

				It("should dial one of IPv4 and IPv6", func() {})

				Context("and dialing IPv4", func() {
					BeforeEach(func() {
						dialIPVersion = config.IPVersionV4 // overrides ipVersion
						validIPs = []string{autoAnswerIPv4.String()}
					})

					It("should use IPv4 only", func() {})
				})

				Context("and dialing IPv6", func() {
					BeforeEach(func() {
						dialIPVersion = config.IPVersionV6 // overrides ipVersion
						validIPs = []string{autoAnswerIPv6.String()}
					})

					It("should use IPv6 only", func() {})
				})
			})

			Context("using v4", func() {
				BeforeEach(func() {
					sutConfig.ConnectIPVersion = config.IPVersionV4
					validIPs = []string{autoAnswerIPv4.String()}
				})

				It("should dial IPv4 only", func() {})

				It("should ignore the dial IP version", func() {
					dialIPVersion = config.IPVersionV6 // overridden by ipVersion
				})
			})

			Context("using v6", func() {
				BeforeEach(func() {
					sutConfig.ConnectIPVersion = config.IPVersionV6
					validIPs = []string{autoAnswerIPv6.String()}
				})

				It("should dial IPv6 only", func() {})

				It("should ignore the dial IP version", func() {
					dialIPVersion = config.IPVersionV4 // overridden by ipVersion
				})
			})
		})
	})

	Describe("multiple upstreams", func() {
		var (
			mockUpstream1 *MockUDPUpstreamServer
			mockUpstream2 *MockUDPUpstreamServer
		)

		BeforeEach(func() {
			mockUpstream1 = NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
			DeferCleanup(mockUpstream1.Close)

			mockUpstream2 = NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
			DeferCleanup(mockUpstream1.Close)

			sutConfig.BootstrapDNS = []config.BootstrappedUpstreamConfig{
				{Upstream: mockUpstream1.Start()},
				{Upstream: mockUpstream2.Start()},
			}
		})

		It("uses both", func() {
			_, err := sut.resolve(ctx, "example.com.", []dns.Type{dns.Type(dns.TypeA)})

			Expect(err).To(Succeed())

			Eventually(func(g Gomega) {
				g.Expect(mockUpstream1.GetCallCount()).To(Equal(1))
				g.Expect(mockUpstream2.GetCallCount()).To(Equal(1))
			}, "100ms").Should(Succeed())
		})
	})
})
