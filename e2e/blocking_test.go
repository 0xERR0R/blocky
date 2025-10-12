package e2e

import (
	"context"
	"net"
	"net/http"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Domain blocking functionality", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		// Setup mock DNS server for all tests
		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
		Expect(err).Should(Succeed())
	})

	Describe("External blocklist loading", func() {
		Context("when blocklist is unavailable", func() {
			Context("with loading.strategy = blocking", func() {
				BeforeEach(func(ctx context.Context) {
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"log:",
						"  level: warn",
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka",
						"blocking:",
						"  loading:",
						"    strategy: blocking",
						"  denylists:",
						"    ads:",
						"      - http://wrong.domain.url/list.txt",
						"  clientGroupsBlock:",
						"    default:",
						"      - ads",
					)
					Expect(err).Should(Succeed())
				})

				It("starts with warning and continues to function", func(ctx context.Context) {
					// Verify DNS resolution still works
					msg := util.NewMsgWithQuestion("google.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("google.com.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))

					// Verify warning in logs
					Expect(getContainerLogs(ctx, blocky)).Should(ContainElement(ContainSubstring("cannot open source: ")))
				})
			})

			Context("with loading.strategy = failOnError", func() {
				BeforeEach(func(ctx context.Context) {
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"log:",
						"  level: warn",
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka",
						"blocking:",
						"  loading:",
						"    strategy: failOnError",
						"  denylists:",
						"    ads:",
						"      - http://wrong.domain.url/list.txt",
						"  clientGroupsBlock:",
						"    default:",
						"      - ads",
					)
					Expect(err).Should(HaveOccurred())

					// Verify container exit status
					state, err := blocky.State(ctx)
					Expect(err).Should(Succeed())
					Expect(state.ExitCode).Should(Equal(1))
				})

				It("fails to start with appropriate error message", func(ctx context.Context) {
					Eventually(blocky.IsRunning, "5s", "2ms").Should(BeFalse())
					Expect(getContainerLogs(ctx, blocky)).
						Should(ContainElement(ContainSubstring("Error: can't start server: 1 error occurred")))
				})
			})
		})
	})

	Describe("Domain blocking", func() {
		Context("with available external blocklists", func() {
			BeforeEach(func(ctx context.Context) {
				// Create HTTP server with blocklist
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blockeddomain.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("blocks domains listed in external blocklists", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("blockeddomain.com.", A)

				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("blockeddomain.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 6*60*60)),
						))

				// No errors should be logged
				Expect(getContainerLogs(ctx, blocky)).Should(BeEmpty())
			})
		})
	})

	// Note: Allowlist-only mode test (4.1) is not fully implemented here because
	// allowlists in Blocky work as exceptions to denylists, not as standalone allow-only mode.
	// The allowlist functionality is tested in conjunction with denylists in other tests.

	Describe("Wildcard blocking", func() {
		Context("with wildcard patterns in blocklist", func() {
			BeforeEach(func(ctx context.Context) {
				// Create HTTP server with wildcard blocklist
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt",
					"*.blocked.com",
					"*.ads.example.com",
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("blocks domains matching wildcard patterns", func(ctx context.Context) {
				By("blocking the domain", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("blocked.com.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 6*60*60)),
							))
				})

				By("blocking subdomains", func() {
					msg := util.NewMsgWithQuestion("subdomain.blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("subdomain.blocked.com.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 6*60*60)),
							))

					msg = util.NewMsgWithQuestion("deep.sub.blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("deep.sub.blocked.com.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 6*60*60)),
							))
				})

				By("blocking specific subdomain wildcards", func() {
					msg := util.NewMsgWithQuestion("tracker.ads.example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("tracker.ads.example.com.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 6*60*60)),
							))
				})

				By("allowing non-matching domains", func() {
					msg := util.NewMsgWithQuestion("google.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("google.com.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})
			})
		})
	})

	Describe("Regex blocking", func() {
		Context("with regex patterns in blocklist", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS for all domains that should resolve
				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet,
					`A google.com/NOERROR("A 1.2.3.4 123")`,
					`A apple.fr/NOERROR("A 1.2.3.4 123")`,
				)
				Expect(err).Should(Succeed())

				// Create HTTP server with regex blocklist
				// Note: Single backslash in regex patterns for blocky
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt",
					"/^ad[sx]?./",
					"/^tracker[0-9]+.example.com$/",
					"/^apple.(de|com)$/",
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka2",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("blocks domains matching regex patterns", func(ctx context.Context) {
				By("blocking domains matching prefix pattern", func() {
					msg := util.NewMsgWithQuestion("ad.example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("ad.example.com.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 6*60*60)),
							))

					msg = util.NewMsgWithQuestion("ads.example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("ads.example.com.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 6*60*60)),
							))

					msg = util.NewMsgWithQuestion("adx.example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("adx.example.com.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 6*60*60)),
							))
				})

				By("blocking domains matching numeric pattern", func() {
					msg := util.NewMsgWithQuestion("tracker123.example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("tracker123.example.com.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 6*60*60)),
							))
				})

				By("blocking domains matching alternation pattern", func() {
					msg := util.NewMsgWithQuestion("apple.de.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("apple.de.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 6*60*60)),
							))

					msg = util.NewMsgWithQuestion("apple.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("apple.com.", A, "0.0.0.0"),
								HaveTTL(BeNumerically("==", 6*60*60)),
							))
				})

				By("allowing non-matching domains", func() {
					msg := util.NewMsgWithQuestion("google.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("google.com.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))

					// apple.fr should not match the pattern
					msg = util.NewMsgWithQuestion("apple.fr.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("apple.fr.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})
			})
		})
	})

	Describe("Block types", func() {
		Context("with blockType: zeroIP (default)", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blocked.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"blocking:",
					"  blockType: zeroIP",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("returns zero IP for blocked domains", func(ctx context.Context) {
				By("returning 0.0.0.0 for A records", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
				})

				By("returning :: for AAAA records", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", AAAA)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Answer).Should(HaveLen(1))
					Expect(resp.Answer[0].String()).Should(ContainSubstring("::"))
				})
			})
		})

		Context("with blockType: nxDomain", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blocked.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"blocking:",
					"  blockType: nxDomain",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("returns NXDOMAIN for blocked domains", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("blocked.com.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
				Expect(resp.Answer).Should(BeEmpty())
			})
		})

		Context("with blockType: custom IPs", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blocked.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"blocking:",
					"  blockType: 192.168.1.1,2001:db8::1",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("returns custom IPs for blocked domains", func(ctx context.Context) {
				By("returning custom IPv4 for A records", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "192.168.1.1"))
				})

				By("returning custom IPv6 for AAAA records", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", AAAA)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", AAAA, "2001:db8::1"))
				})
			})
		})
	})

	Describe("Block TTL", func() {
		Context("with custom blockTTL", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blocked.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"blocking:",
					"  blockTTL: 1m",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("uses the configured TTL for blocked responses", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("blocked.com.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("blocked.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 60)), // 1m = 60s
						))
			})
		})
	})

	Describe("IP blocking", func() {
		Context("with IP addresses in blocklist", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS that returns a blocked IP
				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet,
					`A tracking.example.com/NOERROR("A 192.168.100.50 300")`,
					`A safe.example.com/NOERROR("A 8.8.8.8 300")`,
				)
				Expect(err).Should(Succeed())

				// Create HTTP server with IP blocklist
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "192.168.100.50")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka2",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("blocks domains that resolve to blocked IPs", func(ctx context.Context) {
				By("blocking domains with IPs in the blocklist", func() {
					msg := util.NewMsgWithQuestion("tracking.example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("tracking.example.com.", A, "0.0.0.0"))
				})

				By("allowing domains with IPs not in the blocklist", func() {
					msg := util.NewMsgWithQuestion("safe.example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("safe.example.com.", A, "8.8.8.8"))
				})
			})
		})
	})

	Describe("CNAME blocking", func() {
		Context("with CNAME targets in blocklist", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS with CNAME records
				// Note: Blocky blocks based on CNAME targets in the response
				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet,
					`A alias.example.com/NOERROR("CNAME tracker.ads.com. 300", "A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				// Create HTTP server with CNAME target blocklist
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "tracker.ads.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka2",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("blocks domains with CNAME targets in the blocklist", func(ctx context.Context) {
				By("blocking domains that CNAME to blocked domains", func() {
					msg := util.NewMsgWithQuestion("alias.example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("alias.example.com.", A, "0.0.0.0"))
				})
			})
		})
	})

	Describe("Dynamic blocking control via API", func() {
		Context("with HTTP API enabled", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS to respond to blocked.com
				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet,
					`A blocked.com/NOERROR("A 5.6.7.8 300")`,
					`A google.com/NOERROR("A 1.2.3.4 123")`,
				)
				Expect(err).Should(Succeed())

				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blocked.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka2",
					"ports:",
					"  http: 4000",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("can enable and disable blocking via API", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				baseURL := "http://" + net.JoinHostPort(host, port)

				By("verifying blocking is enabled by default", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
				})

				By("disabling blocking via API", func() {
					resp, err := http.Get(baseURL + "/api/blocking/disable")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))

					// Verify blocked domain now resolves normally from upstream
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "5.6.7.8"))
				})

				By("re-enabling blocking via API", func() {
					resp, err := http.Get(baseURL + "/api/blocking/enable")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))

					// Verify domain is blocked again
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
				})

				By("checking blocking status via API", func() {
					resp, err := http.Get(baseURL + "/api/blocking/status")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})
			})
		})
	})

	Describe("List refresh via API", func() {
		Context("with HTTP API enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blocked.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"ports:",
					"  http: 4000",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("can refresh blocklists via API", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				baseURL := "http://" + net.JoinHostPort(host, port)

				By("triggering list refresh via API", func() {
					resp, err := http.Post(baseURL+"/api/lists/refresh", "application/json", nil)
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})

				By("verifying blocking still works after refresh", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
				})
			})
		})
	})
})
