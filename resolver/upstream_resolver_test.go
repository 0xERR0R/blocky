package resolver

import (
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
		sutConfig config.Upstream
	)

	BeforeEach(func() {
		sutConfig = config.Upstream{Host: "localhost"}
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

				upstream := mockUpstream.Start()
				sut := newUpstreamResolverUnchecked(upstream, nil)

				Expect(sut.Resolve(newRequest("example.com.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "123.124.122.122"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveTTL(BeNumerically("==", 123)),
							HaveReason(fmt.Sprintf("RESOLVED (%s)", upstream))),
					)
			})
		})
		When("Configured DNS resolver can't resolve query", func() {
			It("should return response code from DNS upstream", func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerError(dns.RcodeNameError)
				DeferCleanup(mockUpstream.Close)

				upstream := mockUpstream.Start()
				sut := newUpstreamResolverUnchecked(upstream, nil)

				Expect(sut.Resolve(newRequest("example.com.", A))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeNameError),
							HaveReason(fmt.Sprintf("RESOLVED (%s)", upstream))),
					)
			})
		})
		When("Configured DNS resolver fails", func() {
			It("should return error", func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
					return nil
				})
				DeferCleanup(mockUpstream.Close)
				upstream := mockUpstream.Start()
				sut := newUpstreamResolverUnchecked(upstream, nil)

				_, err := sut.Resolve(newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())
			})
		})
		When("Timeout occurs", func() {
			var counter int32
			var attemptsWithTimeout int32
			var sut *UpstreamResolver
			BeforeEach(func() {
				resolveFn := func(request *dns.Msg) (response *dns.Msg) {
					atomic.AddInt32(&counter, 1)
					// timeout on first x attempts
					if atomic.LoadInt32(&counter) <= atomic.LoadInt32(&attemptsWithTimeout) {
						time.Sleep(110 * time.Millisecond)
					}
					response, err := util.NewMsgWithAnswer("example.com", 123, A, "123.124.122.122")
					Expect(err).Should(Succeed())

					return response
				}
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerFn(resolveFn)
				DeferCleanup(mockUpstream.Close)

				upstream := mockUpstream.Start()

				sut = newUpstreamResolverUnchecked(upstream, nil)
				sut.upstreamClient.(*dnsUpstreamClient).udpClient.Timeout = 100 * time.Millisecond
			})
			It("should perform a retry with 3 attempts", func() {
				By("2 attempts with timeout -> should resolve with third attempt", func() {
					atomic.StoreInt32(&counter, 0)
					atomic.StoreInt32(&attemptsWithTimeout, 2)

					Expect(sut.Resolve(newRequest("example.com.", A))).
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
					_, err := sut.Resolve(newRequest("example.com.", A))
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("i/o timeout"))
				})
			})
		})
	})

	Describe("Using Dns over HTTP (DOH) upstream", func() {
		var (
			sut              *UpstreamResolver
			upstream         config.Upstream
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
			upstream = newTestDOHUpstream(respFn, modifyHTTPRespFn)
			sut = newUpstreamResolverUnchecked(upstream, nil)

			// use insecure certificates for test doh upstream
			sut.upstreamClient.(*httpUpstreamClient).client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			}
		})
		When("Configured DOH resolver can resolve query", func() {
			It("should return answer from DNS upstream", func() {
				Expect(sut.Resolve(newRequest("example.com.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "123.124.122.122"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveTTL(BeNumerically("==", 123)),
							HaveReason(fmt.Sprintf("RESOLVED (https://%s:%d)", upstream.Host, upstream.Port)),
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
				_, err := sut.Resolve(newRequest("example.com.", A))
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
				_, err := sut.Resolve(newRequest("example.com.", A))
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
				_, err := sut.Resolve(newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("can't unpack message"))
			})
		})
		When("Configured DOH resolver does not respond", func() {
			JustBeforeEach(func() {
				sut = newUpstreamResolverUnchecked(config.Upstream{
					Net:  config.NetProtocolHttps,
					Host: "wronghost.example.com",
				}, systemResolverBootstrap)
			})
			It("should return error", func() {
				_, err := sut.Resolve(newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(Or(
					ContainSubstring("no such host"),
					ContainSubstring("i/o timeout"),
					ContainSubstring("Temporary failure in name resolution")))
			})
		})
	})
})
