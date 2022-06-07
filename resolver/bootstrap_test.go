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

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Bootstrap", Label("bootstrap"), func() {
	var (
		sut       *Bootstrap
		sutConfig *config.Config

		err error
	)

	BeforeEach(func() {
		sutConfig = &config.Config{
			BootstrapDNS: config.BootstrapConfig{
				Upstream: config.Upstream{
					Net:  config.NetProtocolTcpTls,
					Host: "bootstrapUpstream.invalid",
				},
				IPs: []net.IP{net.IPv4zero},
			},
		}
	})

	JustBeforeEach(func() {
		sut, err = NewBootstrap(sutConfig)
		Expect(err).Should(Succeed())
	})

	Describe("configuration", func() {
		When("is not specified", func() {
			BeforeEach(func() {
				sutConfig = &config.Config{}
			})

			It("should use the system resolver", func() {
				usedSystemResolver := make(chan bool, 10)

				sut.systemResolver = &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						usedSystemResolver <- true

						return nil, errors.New("don't actually do anything")
					},
				}

				_, err := sut.resolveUpstream(nil, "example.com")
				Expect(err).ShouldNot(Succeed())
				Expect(usedSystemResolver).Should(Receive(BeTrue()))
			})

			Describe("HTTP transport", func() {
				It("should use the system resolver", func() {
					transport := sut.NewHTTPTransport()

					Expect(transport).ShouldNot(BeNil())
					Expect(*transport).Should(BeZero()) // nolint:govet
				})
			})
		})

		Context("using TCP UDP", func() {
			When("IP is set", func() {
				BeforeEach(func() {
					sutConfig = &config.Config{
						BootstrapDNS: config.BootstrapConfig{
							Upstream: config.Upstream{
								Net:  config.NetProtocolTcpUdp,
								Host: "0.0.0.0",
							},
						},
					}
				})
				It("accepts an IP", func() {
					Expect(sut).ShouldNot(BeNil())
					Expect(sut.upstreamIPs).Should(ContainElement(net.IPv4zero))
				})
			})
			When("IP is invalid", func() {
				It("requires an IP", func() {
					cfg := config.Config{
						BootstrapDNS: config.BootstrapConfig{
							Upstream: config.Upstream{
								Net:  config.NetProtocolTcpUdp,
								Host: "bootstrapUpstream.invalid",
							},
						},
					}

					_, err := NewBootstrap(&cfg)
					Expect(err).ShouldNot(Succeed())
					Expect(err.Error()).Should(ContainSubstring("is not an IP"))
				})
			})
		})

		Context("using encrypted DNS", func() {
			When("IP is invalid", func() {
				It("requires bootstrap IPs", func() {
					cfg := config.Config{
						BootstrapDNS: config.BootstrapConfig{
							Upstream: config.Upstream{
								Net:  config.NetProtocolTcpTls,
								Host: "bootstrapUpstream.invalid",
							},
						},
					}

					_, err := NewBootstrap(&cfg)
					Expect(err).ShouldNot(Succeed())
					Expect(err.Error()).Should(ContainSubstring("bootstrapDns.IPs is required"))
				})
			})
		})
	})

	Describe("resolving", func() {
		var bootstrapUpstream *MockResolver

		BeforeEach(func() {
			bootstrapUpstream = &MockResolver{}

			sutConfig.BootstrapDNS = config.BootstrapConfig{
				Upstream: config.Upstream{
					Net:  config.NetProtocolTcpTls,
					Host: "bootstrapUpstream.invalid",
				},
				IPs: []net.IP{net.IPv4zero},
			}
		})

		JustBeforeEach(func() {
			sut.resolver = bootstrapUpstream
			sut.upstream = bootstrapUpstream
		})

		AfterEach(func() {
			bootstrapUpstream.AssertExpectations(GinkgoT())
		})

		When("called from bootstrap.upstream", func() {
			It("uses hardcoded IPs", func() {
				ips, err := sut.resolveUpstream(bootstrapUpstream, "host")

				Expect(err).Should(Succeed())
				Expect(ips).Should(Equal(sutConfig.BootstrapDNS.IPs))
			})
		})

		When("hostname is an IP", func() {
			It("returns immediately", func() {
				ips, err := sut.resolve("0.0.0.0", v4v6QTypes)

				Expect(err).Should(Succeed())
				Expect(ips).Should(ContainElement(net.IPv4zero))
			})
		})

		When("upstream returns an IPv6", func() {
			It("it is used", func() {
				bootstrapResponse, err := util.NewMsgWithAnswer(
					"localhost.", 123, dns.Type(dns.TypeAAAA), net.IPv6loopback.String(),
				)
				Expect(err).Should(Succeed())

				bootstrapUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: bootstrapResponse}, nil)

				ips, err := sut.resolve("localhost", []dns.Type{dns.Type(dns.TypeAAAA)})

				Expect(err).Should(Succeed())
				Expect(ips).Should(HaveLen(1))
				Expect(ips).Should(ContainElement(net.IPv6loopback))
			})
		})

		When("upstream returns an error", func() {
			It("it is returned", func() {
				resolveErr := errors.New("test")

				bootstrapUpstream.On("Resolve", mock.Anything).Return(nil, resolveErr)

				ips, err := sut.resolve("localhost", []dns.Type{dns.Type(dns.TypeA)})

				Expect(err).ShouldNot(Succeed())
				Expect(err.Error()).Should(ContainSubstring(resolveErr.Error()))
				Expect(ips).Should(HaveLen(0))
			})
		})

		When("upstream returns an error response", func() {
			It("an error is returned", func() {
				bootstrapResponse := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}

				bootstrapUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: bootstrapResponse}, nil)

				ips, err := sut.resolve("unknownhost.invalid", []dns.Type{dns.Type(dns.TypeA)})

				Expect(err).ShouldNot(Succeed())
				Expect(err.Error()).Should(ContainSubstring("no such host"))
				Expect(ips).Should(HaveLen(0))
			})
		})

		When("called from another UpstreamResolver", func() {
			It("uses the bootstrap upstream", func() {
				mainReq := &model.Request{
					Req: util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA)),
					Log: logrus.NewEntry(log.Log()),
				}

				mockUpstreamServer := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				DeferCleanup(mockUpstreamServer.Close)
				upstream := mockUpstreamServer.Start()

				upstreamIP := upstream.Host

				bootstrapResponse, err := util.NewMsgWithAnswer(
					"localhost.", 123, dns.Type(dns.TypeA), upstreamIP,
				)
				Expect(err).Should(Succeed())

				bootstrapUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: bootstrapResponse}, nil)

				upstream.Host = "localhost" // force bootstrap to do resolve, and not just return the IP as is

				r := newUpstreamResolverUnchecked(upstream, sut)

				rsp, err := r.Resolve(mainReq)
				Expect(err).Should(Succeed())
				Expect(mockUpstreamServer.GetCallCount()).Should(Equal(1))
				Expect(rsp.Res.Question[0].Name).Should(Equal("example.com."))
				Expect(rsp.Res.Id).ShouldNot(Equal(bootstrapResponse.Id))
			})
		})

		Describe("HTTP Transport", func() {
			It("uses the bootstrap upstream", func() {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(200)
				}))
				DeferCleanup(server.Close)

				url, err := url.Parse(server.URL)
				Expect(err).Should(Succeed())

				host, port, err := net.SplitHostPort(url.Host)
				Expect(err).Should(Succeed())

				bootstrapResponse, err := util.NewMsgWithAnswer(
					"localhost.", 123, dns.Type(dns.TypeA), host,
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

				_, err = t.DialContext(context.Background(), "ip", "!bad-addr!")
				Expect(err).ShouldNot(Succeed())
			})

			It("returns upstream errors", func() {
				resolveErr := errors.New("test")

				bootstrapUpstream.On("Resolve", mock.Anything).Return(nil, resolveErr)

				t := sut.NewHTTPTransport()

				_, err = t.DialContext(context.Background(), "ip", "abc:123")

				Expect(err).ShouldNot(Succeed())
				Expect(err.Error()).Should(ContainSubstring(resolveErr.Error()))
			})

			It("errors for unknown host", func() {
				bootstrapResponse := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}

				bootstrapUpstream.On("Resolve", mock.Anything).Return(&model.Response{Res: bootstrapResponse}, nil)

				t := sut.NewHTTPTransport()

				_, err = t.DialContext(context.Background(), "ip", "abc:123")

				Expect(err).ShouldNot(Succeed())
				Expect(err.Error()).Should(ContainSubstring("no such host"))
			})
		})
	})
})
