package resolver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
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
			var counter atomic.Int32
			var attemptsWithTimeout atomic.Int32
			BeforeEach(func() {
				resolveFn := func(request *dns.Msg) *dns.Msg {
					// timeout on first x attempts
					if counter.Add(1) <= attemptsWithTimeout.Load() {
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
					counter.Store(0)
					attemptsWithTimeout.Store(2)

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
					counter.Store(0)
					attemptsWithTimeout.Store(3)
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

	Describe("Using DNS over QUIC (DoQ) upstream", func() {
		When("Configured DoQ resolver can resolve query", func() {
			It("should return answer from DoQ upstream", func() {
				mockUpstream := NewMockDoQUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				upstream := mockUpstream.Start()

				sutConfig.Upstream = upstream
				sut = newUpstreamResolverUnchecked(sutConfig, nil)

				// Override TLS config to skip certificate verification for test server
				quicClient := sut.upstreamClient.(*quicUpstreamClient)
				quicClient.tlsConfig.InsecureSkipVerify = true

				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "123.124.122.122"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveTTL(BeNumerically("==", 123)),
						))
			})
		})

		When("DoQ upstream returns error code", func() {
			It("should return error response", func() {
				mockUpstream := NewMockDoQUpstreamServer().WithAnswerError(dns.RcodeServerFailure)
				upstream := mockUpstream.Start()

				sutConfig.Upstream = upstream
				sut = newUpstreamResolverUnchecked(sutConfig, nil)

				quicClient := sut.upstreamClient.(*quicUpstreamClient)
				quicClient.tlsConfig.InsecureSkipVerify = true

				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
					Should(HaveReturnCode(dns.RcodeServerFailure))
			})
		})

		When("DoQ upstream is not reachable", func() {
			It("should return error", func() {
				sutConfig.Upstream = config.Upstream{
					Net:  config.NetProtocolQuic,
					Host: "127.0.0.1",
					Port: 1, // nothing listening here
				}
				sut = newUpstreamResolverUnchecked(sutConfig, systemResolverBootstrap)

				_, err := sut.Resolve(ctx, newRequest("example.com.", A))
				Expect(err).Should(HaveOccurred())
			})
		})

		When("Multiple queries are sent", func() {
			It("should reuse the QUIC connection", func() {
				mockUpstream := NewMockDoQUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				upstream := mockUpstream.Start()

				sutConfig.Upstream = upstream
				sut = newUpstreamResolverUnchecked(sutConfig, nil)

				quicClient := sut.upstreamClient.(*quicUpstreamClient)
				quicClient.tlsConfig.InsecureSkipVerify = true

				for range 3 {
					Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "123.124.122.122"),
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				}

				Expect(mockUpstream.GetCallCount()).Should(Equal(3))
				// Verify only a single QUIC connection was established (not one per query)
				Expect(mockUpstream.GetConnCount()).Should(Equal(1))
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
				Expect(err.Error()).Should(ContainSubstring("1 pinned hash"))
				// Should suggest updating DNS stamp
				Expect(err.Error()).Should(ContainSubstring("try updating DNS stamp"))
			})
		})
	})
})

var _ = Describe("UpstreamResolver connection pooling", Label("upstreamResolver", "connPool"), func() {
	var (
		ctx      context.Context
		cancelFn context.CancelFunc
	)

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)
	})

	Describe("TLS session cache (Fix A)", func() {
		It("is enabled for DoT upstreams", func() {
			cfg := newUpstreamConfig(
				config.Upstream{Net: config.NetProtocolTcpTls, Host: "localhost", Port: 853},
				defaultUpstreamsConfig,
			)

			client, ok := createUpstreamClient(cfg).(*dnsUpstreamClient)
			Expect(ok).Should(BeTrue())
			Expect(client.tcpClient.TLSConfig.ClientSessionCache).ShouldNot(BeNil())
		})

		It("is enabled for DoH upstreams", func() {
			cfg := newUpstreamConfig(
				config.Upstream{Net: config.NetProtocolHttps, Host: "localhost", Port: 443, Path: "/dns-query"},
				defaultUpstreamsConfig,
			)

			client, ok := createUpstreamClient(cfg).(*httpUpstreamClient)
			Expect(ok).Should(BeTrue())

			transport, ok := client.client.Transport.(*http.Transport)
			Expect(ok).Should(BeTrue())
			Expect(transport.TLSClientConfig.ClientSessionCache).ShouldNot(BeNil())
		})
	})

	Describe("TLS session resumption with certificate pinning (Fix #1)", func() {
		// Go does not invoke VerifyPeerCertificate (our pinning check) on resumed
		// TLS sessions, so resumption must be disabled when a cert is pinned —
		// otherwise pooled re-dials would silently skip the pin.
		pinnedFingerprint := []config.CertificateFingerprint{make([]byte, sha256.Size)}

		It("is disabled for cert-pinned DoT upstreams", func() {
			cfg := newUpstreamConfig(
				config.Upstream{
					Net: config.NetProtocolTcpTls, Host: "localhost", Port: 853,
					CertificateFingerprints: pinnedFingerprint,
				},
				defaultUpstreamsConfig,
			)

			client, ok := createUpstreamClient(cfg).(*dnsUpstreamClient)
			Expect(ok).Should(BeTrue())
			Expect(client.tcpClient.TLSConfig.ClientSessionCache).Should(BeNil())
		})

		It("is disabled for cert-pinned DoH upstreams", func() {
			cfg := newUpstreamConfig(
				config.Upstream{
					Net: config.NetProtocolHttps, Host: "localhost", Port: 443, Path: "/dns-query",
					CertificateFingerprints: pinnedFingerprint,
				},
				defaultUpstreamsConfig,
			)

			client, ok := createUpstreamClient(cfg).(*httpUpstreamClient)
			Expect(ok).Should(BeTrue())

			transport, ok := client.client.Transport.(*http.Transport)
			Expect(ok).Should(BeTrue())
			Expect(transport.TLSClientConfig.ClientSessionCache).Should(BeNil())
		})
	})

	Describe("DoT connection reuse (Fix B)", func() {
		// newDoTResolver builds a resolver pointing at the mock server and trusts
		// its self-signed certificate. The pool shares the tcpClient's TLS config,
		// so InsecureSkipVerify applies to pooled dials too.
		newDoTResolver := func(upstream config.Upstream) *UpstreamResolver {
			cfg := newUpstreamConfig(upstream, defaultUpstreamsConfig)
			r := newUpstreamResolverUnchecked(cfg, systemResolverBootstrap)
			client := r.upstreamClient.(*dnsUpstreamClient)
			client.tcpClient.TLSConfig.InsecureSkipVerify = true

			// Close the pool after the spec so idle client connections don't linger.
			DeferCleanup(client.Close)

			return r
		}

		It("reuses a single connection across multiple queries", func() {
			mock := NewMockDoTUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
			sut := newDoTResolver(mock.Start())

			for range 3 {
				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
					Should(SatisfyAll(
						BeDNSRecord("example.com.", A, "123.124.122.122"),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))
			}

			Expect(mock.GetCallCount()).Should(Equal(3))
			// A single connection serves all three queries.
			Expect(mock.GetConnCount()).Should(Equal(1))

			stats := sut.upstreamClient.(*dnsUpstreamClient).pool.stats()
			Expect(stats.dialed).Should(Equal(int64(1)))
			Expect(stats.reused).Should(Equal(int64(2)))
		})

		It("transparently recovers when the upstream closed a pooled connection", func() {
			// The server drops the connection after each query, so every reuse
			// hits a stale connection and must fall back to a fresh dial.
			mock := NewMockDoTUpstreamServer().
				WithAnswerRR("example.com 123 IN A 123.124.122.122").
				WithCloseAfter(1)
			sut := newDoTResolver(mock.Start())

			for range 2 {
				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
					Should(SatisfyAll(
						BeDNSRecord("example.com.", A, "123.124.122.122"),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))
			}

			Expect(mock.GetCallCount()).Should(Equal(2))
			// A fresh connection per query because each was closed server-side.
			Expect(mock.GetConnCount()).Should(Equal(2))

			// The second query took the pooled connection, found it broken on
			// exchange, and recovered with a fresh dial — never surfacing an error.
			// reused counts only successful reuses, so it stays 0 here; the broken
			// reuse is reflected by retried instead.
			stats := sut.upstreamClient.(*dnsUpstreamClient).pool.stats()
			Expect(stats.dialed).Should(Equal(int64(2)))
			Expect(stats.reused).Should(Equal(int64(0)))
			Expect(stats.retried).Should(Equal(int64(1)))
		})

		It("closes pooled connections when the client is closed (Fix #2)", func() {
			mock := NewMockDoTUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
			sut := newDoTResolver(mock.Start())

			Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
				Should(HaveReturnCode(dns.RcodeSuccess))

			client := sut.upstreamClient.(*dnsUpstreamClient)
			Expect(client.pool.idleCount()).Should(Equal(1))

			Expect(client.Close()).Should(Succeed())
			Expect(client.pool.idleCount()).Should(Equal(0))
		})

		It("does not leak server goroutines when the mock is closed (Fix #5)", func() {
			mock := NewMockDoTUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
			sut := newDoTResolver(mock.Start())

			Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
				Should(HaveReturnCode(dns.RcodeSuccess))

			// The query left a handleConn goroutine serving the accepted connection.
			Eventually(mock.openConnCount).Should(Equal(1))

			mock.Close()

			// Closing the server must close accepted connections too, so handleConn
			// unblocks from ReadMsg and exits instead of leaking.
			Eventually(mock.openConnCount).Should(Equal(0))
		})
	})

	Describe("TLS session resumption (Fix A)", func() {
		// The fix configures a ClientSessionCache. We assert the client-side
		// effect we control: a session ticket is cached and then offered on the
		// next dial. (Whether a given upstream completes resumption is up to the
		// server; real DoT resolvers do.)
		It("caches the TLS session and offers it on reconnect", func() {
			// The server drops each connection after 3 queries, so the 4th query
			// must reconnect — by which point the session ticket has been cached.
			mock := NewMockDoTUpstreamServer().
				WithAnswerRR("example.com 123 IN A 123.124.122.122").
				WithCloseAfter(3)
			cfg := newUpstreamConfig(mock.Start(), defaultUpstreamsConfig)
			sut := newUpstreamResolverUnchecked(cfg, systemResolverBootstrap)

			cache := &observingSessionCache{inner: tls.NewLRUClientSessionCache(0)}
			client := sut.upstreamClient.(*dnsUpstreamClient)
			client.tcpClient.TLSConfig.InsecureSkipVerify = true
			client.tcpClient.TLSConfig.ClientSessionCache = cache
			DeferCleanup(client.Close)

			for range 4 {
				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
					Should(HaveReturnCode(dns.RcodeSuccess))
			}

			// A reconnect happened: 3 queries on the first connection, then a fresh one.
			Expect(mock.GetConnCount()).Should(BeNumerically(">=", 2))
			// Fix A: the client cached a session ticket and offered it on the reconnect.
			Expect(cache.puts.Load()).Should(BeNumerically(">=", 1))
			Expect(cache.getHits.Load()).Should(BeNumerically(">=", 1))
		})
	})
})

// observingSessionCache wraps a tls.ClientSessionCache to count non-nil Puts
// (sessions cached) and Get hits (sessions offered on reconnect), so tests can
// assert that TLS session resumption is enabled and exercised.
type observingSessionCache struct {
	inner   tls.ClientSessionCache
	puts    atomic.Int32
	getHits atomic.Int32
}

func (o *observingSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	cs, ok := o.inner.Get(key)
	if ok {
		o.getHits.Add(1)
	}

	return cs, ok
}

func (o *observingSessionCache) Put(key string, cs *tls.ClientSessionState) {
	if cs != nil {
		o.puts.Add(1)
	}

	o.inner.Put(key, cs)
}
