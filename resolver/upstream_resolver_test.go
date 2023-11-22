package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync/atomic"
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

var _ = Describe("UpstreamResolver", Label("upstreamResolver"), func() {
	var (
		sut       *UpstreamResolver
		sutConfig upstreamConfig

		ctx      context.Context
		cancelFn context.CancelFunc
	)

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		sutConfig = newUpstreamConfig(config.Upstream{Host: "localhost"}, defaultUpstreamsConfig)
	})

	JustBeforeEach(func() {
		sut = newUpstreamResolverUnchecked(sutConfig, systemResolverBootstrap)
	})

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
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

	Describe("Using DNS upstream", func() {
		When("Configured DNS resolver can resolve query", func() {
			It("should return answer from DNS upstream", func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				DeferCleanup(mockUpstream.Close)

				sutConfig.Upstream = mockUpstream.Start()
				sut := newUpstreamResolverUnchecked(sutConfig, nil)

				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "123.124.122.122"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveTTL(BeNumerically("==", 123)),
							HaveReason(fmt.Sprintf("RESOLVED (%s)", sutConfig.Upstream))),
					)
			})
		})
		When("Configured DNS resolver can't resolve query", func() {
			It("should return response code from DNS upstream", func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerError(dns.RcodeNameError)
				DeferCleanup(mockUpstream.Close)

				sutConfig.Upstream = mockUpstream.Start()
				sut := newUpstreamResolverUnchecked(sutConfig, nil)

				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeNameError),
							HaveReason(fmt.Sprintf("RESOLVED (%s)", sutConfig.Upstream))),
					)
			})
		})
		When("Configured DNS resolver fails", func() {
			It("should return error", func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
					return nil
				})
				DeferCleanup(mockUpstream.Close)
				sutConfig.Upstream = mockUpstream.Start()
				sut := newUpstreamResolverUnchecked(sutConfig, nil)

				_, err := sut.Resolve(ctx, newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())
			})
		})
		When("Timeout occurs", func() {
			var counter int32
			var attemptsWithTimeout int32
			BeforeEach(func() {
				timeout := sutConfig.Timeout.ToDuration() // avoid data race

				resolveFn := func(request *dns.Msg) *dns.Msg {
					// timeout on first x attempts
					if atomic.AddInt32(&counter, 1) <= atomic.LoadInt32(&attemptsWithTimeout) {
						time.Sleep(2 * timeout)
					}

					response, err := util.NewMsgWithAnswer("example.com", 123, A, "123.124.122.122")
					Expect(err).Should(Succeed())

					return response
				}

				mockUpstream := NewMockUDPUpstreamServer().WithAnswerFn(resolveFn)
				DeferCleanup(mockUpstream.Close)

				sutConfig.Upstream = mockUpstream.Start()
			})

			It("should perform a retry with 3 attempts", func() {
				By("2 attempts with timeout -> should resolve with third attempt", func() {
					atomic.StoreInt32(&counter, 0)
					atomic.StoreInt32(&attemptsWithTimeout, 2)

					Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.122"),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
								HaveTTL(BeNumerically("==", 123)),
							))
				})

				By("3 attempts with timeout -> should return error", func() {
					atomic.StoreInt32(&counter, 0)
					atomic.StoreInt32(&attemptsWithTimeout, 3)
					_, err := sut.Resolve(ctx, newRequest("example.com.", A))
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("i/o timeout"))
				})
			})
		})

		When("user request is TCP", func() {
			When("TCP upstream connection fails", func() {
				BeforeEach(func() {
					mockUpstream := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
					DeferCleanup(mockUpstream.Close)

					sutConfig.Upstream = mockUpstream.Start()
				})

				It("should retry with UDP", func() {
					req := newRequest("example.com.", A)
					req.Protocol = RequestProtocolTCP

					Expect(sut.Resolve(ctx, req)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.122"),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
								HaveTTL(BeNumerically("==", 123)),
							))
				})
			})
		})
	})

	Describe("Using Dns over HTTP (DOH) upstream", func() {
		var (
			respFn           func(request *dns.Msg) (response *dns.Msg)
			modifyHTTPRespFn func(w http.ResponseWriter)
		)

		BeforeEach(func() {
			respFn = func(_ *dns.Msg) *dns.Msg {
				response, err := util.NewMsgWithAnswer("example.com", 123, A, "123.124.122.122")

				Expect(err).Should(Succeed())

				return response
			}
		})

		JustBeforeEach(func() {
			sutConfig.Upstream = newTestDOHUpstream(respFn, modifyHTTPRespFn)
			sut = newUpstreamResolverUnchecked(sutConfig, nil)

			// use insecure certificates for test doh upstream
			sut.upstreamClient.(*httpUpstreamClient).client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			}
		})
		When("Configured DOH resolver can resolve query", func() {
			It("should return answer from DNS upstream", func() {
				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "123.124.122.122"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveTTL(BeNumerically("==", 123)),
							HaveReason(fmt.Sprintf("RESOLVED (%s)", sutConfig.Upstream)),
						))
			})
		})
		When("Configured DOH resolver returns wrong http status code", func() {
			BeforeEach(func() {
				modifyHTTPRespFn = func(w http.ResponseWriter) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			It("should return error", func() {
				_, err := sut.Resolve(ctx, newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("http return code should be 200, but received 500"))
			})
		})
		When("Configured DOH resolver returns wrong content type", func() {
			BeforeEach(func() {
				modifyHTTPRespFn = func(w http.ResponseWriter) {
					w.Header().Set("content-type", "text")
				}
			})
			It("should return error", func() {
				_, err := sut.Resolve(ctx, newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(
					ContainSubstring("http return content type should be 'application/dns-message', but was 'text'"))
			})
		})
		When("Configured DOH resolver returns wrong content", func() {
			BeforeEach(func() {
				modifyHTTPRespFn = func(w http.ResponseWriter) {
					_, _ = w.Write([]byte("wrongcontent"))
				}
			})
			It("should return error", func() {
				_, err := sut.Resolve(ctx, newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("can't unpack message"))
			})
		})
		When("Configured DOH resolver does not respond", func() {
			JustBeforeEach(func() {
				sutConfig.Upstream = config.Upstream{
					Net:  config.NetProtocolHttps,
					Host: "wronghost.example.com",
				}

				sut = newUpstreamResolverUnchecked(sutConfig, systemResolverBootstrap)
			})
			It("should return error", func() {
				_, err := sut.Resolve(ctx, newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(Or(
					ContainSubstring("no such host"),
					ContainSubstring("i/o timeout"),
					ContainSubstring("Temporary failure in name resolution")))
			})
		})
	})
})
