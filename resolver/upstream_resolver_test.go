package resolver

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// nolint:gochecknoinits
func init() {
	// Skips the constructor's check
	// Resolves hostnames using system resolver
	skipUpstreamCheck = &Bootstrap{}
}

var _ = Describe("UpstreamResolver", Label("upstreamResolver"), func() {
	Describe("Using DNS upstream", func() {

		When("Configured DNS resolver can resolve query", func() {
			It("should return answer from DNS upstream", func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				DeferCleanup(mockUpstream.Close)

				upstream := mockUpstream.Start()
				sut, _ := NewUpstreamResolver(upstream, skipUpstreamCheck)

				resp, err := sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
				Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.122"))
				Expect(resp.Reason).Should(Equal(fmt.Sprintf("RESOLVED (%s)", upstream.String())))
			})
		})
		When("Configured DNS resolver can't resolve query", func() {
			It("should return response code from DNS upstream", func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerError(dns.RcodeNameError)
				DeferCleanup(mockUpstream.Close)

				upstream := mockUpstream.Start()
				sut, _ := NewUpstreamResolver(upstream, skipUpstreamCheck)

				resp, err := sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
				Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
				Expect(resp.Reason).Should(Equal(fmt.Sprintf("RESOLVED (%s)", upstream.String())))
			})
		})
		When("Configured DNS resolver fails", func() {
			It("should return error", func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
					return nil
				})
				DeferCleanup(mockUpstream.Close)
				upstream := mockUpstream.Start()
				sut, _ := NewUpstreamResolver(upstream, skipUpstreamCheck)

				_, err := sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
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
					response, err := util.NewMsgWithAnswer("example.com", 123, dns.Type(dns.TypeA), "123.124.122.122")
					Expect(err).Should(Succeed())

					return response
				}
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerFn(resolveFn)
				DeferCleanup(mockUpstream.Close)

				upstream := mockUpstream.Start()

				sut, _ = NewUpstreamResolver(upstream, skipUpstreamCheck)
				sut.upstreamClient.(*dnsUpstreamClient).udpClient.Timeout = 100 * time.Millisecond
			})
			It("should perform a retry with 3 attempts", func() {
				By("2 attempts with timeout -> should resolve with third attempt", func() {
					atomic.StoreInt32(&counter, 0)
					atomic.StoreInt32(&attemptsWithTimeout, 2)

					resp, err := sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.122"))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
				})

				By("3 attempts with timeout -> should return error", func() {
					atomic.StoreInt32(&counter, 0)
					atomic.StoreInt32(&attemptsWithTimeout, 3)
					_, err := sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
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
				response, err := util.NewMsgWithAnswer("example.com", 123, dns.Type(dns.TypeA), "123.124.122.122")

				Expect(err).Should(Succeed())

				return response
			}
		})

		JustBeforeEach(func() {
			upstream = TestDOHUpstream(respFn, modifyHTTPRespFn)
			sut, _ = NewUpstreamResolver(upstream, skipUpstreamCheck)

			// use insecure certificates for test doh upstream
			// nolint:gosec
			sut.upstreamClient.(*httpUpstreamClient).client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			}
		})
		When("Configured DOH resolver can resolve query", func() {
			It("should return answer from DNS upstream", func() {
				resp, err := sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
				Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.122"))
				Expect(resp.Reason).Should(Equal(fmt.Sprintf("RESOLVED (https://%s:%d)", upstream.Host, upstream.Port)))
			})
		})
		When("Configured DOH resolver returns wrong http status code", func() {
			BeforeEach(func() {
				modifyHTTPRespFn = func(w http.ResponseWriter) {
					w.WriteHeader(500)
				}
			})
			It("should return error", func() {
				_, err := sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
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
				_, err := sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
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
				_, err := sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("can't unpack message"))
			})
		})
		When("Configured DOH resolver does not respond", func() {
			JustBeforeEach(func() {
				sut, _ = NewUpstreamResolver(config.Upstream{
					Net:  config.NetProtocolHttps,
					Host: "wronghost.example.com",
				}, skipUpstreamCheck)
			})
			It("should return error", func() {
				_, err := sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(Or(ContainSubstring("no such host"), ContainSubstring("i/o timeout")))
			})
		})
	})
	Describe("Configuration", func() {
		When("Configuration is called", func() {
			It("should return nil, because upstream resolver is printed out by other resolvers", func() {
				sut, _ := NewUpstreamResolver(config.Upstream{}, skipUpstreamCheck)

				c := sut.Configuration()

				Expect(c).Should(BeNil())
			})
		})
	})
})
