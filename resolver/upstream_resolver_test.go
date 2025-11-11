package resolver

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
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

				sutConfig.Upstream = mockUpstream.Start()
				sut := newUpstreamResolverUnchecked(sutConfig, nil)

				_, err := sut.Resolve(ctx, newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())
			})
		})
		When("Configured DNS resolver returns ServFail", func() {
			It("should return error", func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerError(dns.RcodeServerFailure)

				sutConfig.Upstream = mockUpstream.Start()
				sut := newUpstreamResolverUnchecked(sutConfig, nil)

				_, err := sut.Resolve(ctx, newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())

				var servErr *UpstreamServerError
				Expect(errors.As(err, &servErr)).Should(BeTrue())
			})
		})
		When("Timeout occurs", func() {
			var counter int32
			var attemptsWithTimeout int32
			BeforeEach(func() {
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

					sutConfig.Upstream = mockUpstream.Start()
				})

				It("should also try with UDP", func() {
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

	Describe("Using DNS over HTTPS (DoH) upstream", func() {
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

		transport := func() *http.Transport {
			upstreamClient := sut.upstreamClient.(*httpUpstreamClient)

			return upstreamClient.client.Transport.(*http.Transport)
		}

		JustBeforeEach(func() {
			sutConfig.Upstream = newTestDOHUpstream(respFn, modifyHTTPRespFn)
			sut = newUpstreamResolverUnchecked(sutConfig, nil)

			// use insecure certificates for test DoH upstream
			transport().TLSClientConfig.InsecureSkipVerify = true
		})

		When("a proxy is configured", func() {
			It("should use it", func() {
				proxy := TestHTTPProxy()

				transport().Proxy = proxy.ReqURL

				_, err := sut.Resolve(ctx, newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())

				upstreamHostPort := net.JoinHostPort(sutConfig.Host, strconv.FormatUint(uint64(sutConfig.Port), 10))
				Expect(proxy.RequestTarget()).Should(Equal(upstreamHostPort))
			})
		})
		When("Configured DoH resolver can resolve query", func() {
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
		When("Configured DoH resolver returns wrong http status code", func() {
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
		When("Configured DoH resolver returns wrong content type", func() {
			BeforeEach(func() {
				modifyHTTPRespFn = func(w http.ResponseWriter) {
					w.Header().Set("Content-Type", "text")
				}
			})
			It("should return error", func() {
				_, err := sut.Resolve(ctx, newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(
					ContainSubstring("http return content type should be 'application/dns-message', but was 'text'"))
			})
		})
		When("Configured DoH resolver returns wrong content", func() {
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
		When("Configured DoH resolver does not respond", func() {
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

	Describe("Certificate Pinning", Label("certificatePinning"), func() {
		var (
			testCert        *x509.Certificate
			testCertHash    [32]byte
			testCertHashB64 config.CertificateFingerprint
			wrongHash       [32]byte
			wrongHashB64    config.CertificateFingerprint
		)

		BeforeEach(func() {
			// Create a test certificate with TBSCertificate data
			// DNS stamps hash the RawTBSCertificate (To-Be-Signed Certificate), not the full certificate
			tbsData := []byte("test certificate data for pinning validation")
			testCert = &x509.Certificate{
				RawTBSCertificate: tbsData,
			}
			testCertHash = sha256.Sum256(testCert.RawTBSCertificate)
			testCertHashB64 = config.CertificateFingerprint(testCertHash[:])

			wrongHash = sha256.Sum256([]byte("wrong certificate data"))
			wrongHashB64 = config.CertificateFingerprint(wrongHash[:])
		})

		When("Certificate matches pinned hash", func() {
			It("should accept the certificate", func() {
				verifier := createCertificatePinningVerifier([]config.CertificateFingerprint{testCertHashB64})
				chains := [][]*x509.Certificate{{testCert}}

				err := verifier(nil, chains)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})

		When("Certificate does not match pinned hash", func() {
			It("should reject the certificate", func() {
				verifier := createCertificatePinningVerifier([]config.CertificateFingerprint{wrongHashB64})
				chains := [][]*x509.Certificate{{testCert}}

				err := verifier(nil, chains)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("certificate pinning failed"))
			})
		})

		When("Certificate chain contains pinned intermediate", func() {
			It("should accept the chain", func() {
				// DNS stamps hash RawTBSCertificate, not the full certificate
				leafCert := &x509.Certificate{RawTBSCertificate: []byte("leaf certificate")}
				intermediateCert := &x509.Certificate{RawTBSCertificate: []byte("intermediate certificate")}
				rootCert := &x509.Certificate{RawTBSCertificate: []byte("root certificate")}

				intermediateHash := sha256.Sum256(intermediateCert.RawTBSCertificate)
				intermediateHashB64 := config.CertificateFingerprint(intermediateHash[:])

				verifier := createCertificatePinningVerifier([]config.CertificateFingerprint{intermediateHashB64})
				chains := [][]*x509.Certificate{{leafCert, intermediateCert, rootCert}}

				err := verifier(nil, chains)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})

		When("No verified chains are provided", func() {
			It("should reject", func() {
				verifier := createCertificatePinningVerifier([]config.CertificateFingerprint{testCertHashB64})
				chains := [][]*x509.Certificate{}

				err := verifier(nil, chains)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("no verified certificate chains"))
			})
		})

		When("Pinned hashes contain invalid lengths", func() {
			It("should pre-filter and only use valid hashes", func() {
				invalidHash := config.CertificateFingerprint([]byte("invalid short hash"))
				verifier := createCertificatePinningVerifier([]config.CertificateFingerprint{
					invalidHash,     // Invalid (too short)
					testCertHashB64, // Valid (32 bytes)
				})
				chains := [][]*x509.Certificate{{testCert}}

				// Should succeed because the valid hash matches
				err := verifier(nil, chains)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})

		When("Multiple valid hashes are pinned", func() {
			It("should accept if any hash matches", func() {
				// DNS stamps hash RawTBSCertificate
				cert1 := &x509.Certificate{RawTBSCertificate: []byte("certificate 1")}
				cert2 := &x509.Certificate{RawTBSCertificate: []byte("certificate 2")}

				hash1 := sha256.Sum256(cert1.RawTBSCertificate)
				hash2 := sha256.Sum256(cert2.RawTBSCertificate)

				verifier := createCertificatePinningVerifier([]config.CertificateFingerprint{
					config.CertificateFingerprint(hash1[:]),
					config.CertificateFingerprint(hash2[:]),
				})

				// Should accept cert1
				chains1 := [][]*x509.Certificate{{cert1}}
				err := verifier(nil, chains1)
				Expect(err).ShouldNot(HaveOccurred())

				// Should also accept cert2
				chains2 := [][]*x509.Certificate{{cert2}}
				err = verifier(nil, chains2)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})

		When("Multiple chains are provided", func() {
			It("should accept if any chain contains a pinned certificate", func() {
				// DNS stamps hash RawTBSCertificate
				cert1 := &x509.Certificate{RawTBSCertificate: []byte("certificate 1")}
				cert2 := &x509.Certificate{RawTBSCertificate: []byte("certificate 2")}

				hash2 := sha256.Sum256(cert2.RawTBSCertificate)
				hash2B64 := config.CertificateFingerprint(hash2[:])

				verifier := createCertificatePinningVerifier([]config.CertificateFingerprint{hash2B64})

				// First chain has cert1 (no match), second chain has cert2 (match)
				chains := [][]*x509.Certificate{
					{cert1},
					{cert2},
				}

				err := verifier(nil, chains)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})

		When("Enhanced error messages for pinning failures", func() {
			It("should provide detailed information when pinning fails", func() {
				// Create multiple certificates in a chain
				cert1 := &x509.Certificate{Raw: []byte("certificate 1")}
				cert2 := &x509.Certificate{Raw: []byte("certificate 2")}
				cert3 := &x509.Certificate{Raw: []byte("certificate 3")}

				// Wrong hash that won't match any certificate
				wrongHash := sha256.Sum256([]byte("wrong certificate"))
				wrongHashB64 := config.CertificateFingerprint(wrongHash[:])

				verifier := createCertificatePinningVerifier([]config.CertificateFingerprint{wrongHashB64})

				// Multiple chains with multiple certs
				chains := [][]*x509.Certificate{
					{cert1, cert2},
					{cert1, cert3},
				}

				err := verifier(nil, chains)

				// Should fail with detailed error message
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("certificate pinning failed"))
				// Should mention certificate count
				Expect(err.Error()).Should(ContainSubstring("checked 4 certificates"))
				// Should mention chain count
				Expect(err.Error()).Should(ContainSubstring("across 2 chains"))
				// Should mention pinned hash count
				Expect(err.Error()).Should(ContainSubstring("1 pinned hashes"))
				// Should suggest updating DNS stamp
				Expect(err.Error()).Should(ContainSubstring("try updating DNS stamp"))
			})
		})
	})
})
