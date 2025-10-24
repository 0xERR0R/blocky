package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Integration tests", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("Full resolver chain integration", Label("integration"), func() {
		When("Multiple resolvers are configured together", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS servers for different purposes
				// Default upstream for general queries
				_, err = createDNSMokkaContainer(ctx, "default-upstream", e2eNet,
					`A google.com/NOERROR("A 8.8.8.8 300")`,
					`A example.com/NOERROR("A 93.184.216.34 300")`,
					`A tracker.analytics.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				// Conditional upstream for local domain
				_, err = createDNSMokkaContainer(ctx, "local-upstream", e2eNet,
					`A server.local/NOERROR("A 192.168.1.100 300")`,
					`A nas.local/NOERROR("A 192.168.1.50 300")`,
				)
				Expect(err).Should(Succeed())

				// Create HTTP server with blocklist
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "blocklist.txt",
					"ads.example.com",
					"tracker.analytics.com",
					"*.malware.com",
				)
				Expect(err).Should(Succeed())

				// Create blocky with a comprehensive configuration
				// This tests the full resolver chain with:
				// - Blocking (with allowlist and denylist)
				// - Custom DNS mappings
				// - Conditional upstream forwarding
				// - Caching
				// - Query logging (console)
				// - Prometheus metrics
				// - Client groups
				// - Special use domain names handling
				// - Filtering
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: info",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - default-upstream",
					"ports:",
					"  http: 4000",
					"# Blocking configuration with client groups",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/blocklist.txt",
					"  allowlists:",
					"    exceptions:",
					"      - example.com",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
					"  blockType: nxDomain",
					"  blockTTL: 1m",
					"# Custom DNS mappings",
					"customDNS:",
					"  mapping:",
					"    custom.local: 10.0.0.1",
					"    internal.example.com: 172.16.0.10,172.16.0.11",
					"# Conditional upstream for .local domains",
					"conditional:",
					"  mapping:",
					"    local: local-upstream",
					"# Caching configuration",
					"caching:",
					"  minTime: 5s",
					"  maxTime: 30m",
					"  prefetching: true",
					"  prefetchThreshold: 5",
					"# Query logging to console",
					"queryLog:",
					"  type: console",
					"  fields:",
					"    - clientIP",
					"    - clientName",
					"    - responseReason",
					"    - responseAnswer",
					"    - question",
					"    - duration",
					"# Prometheus metrics",
					"prometheus:",
					"  enable: true",
					"  path: /metrics",
					"# Special use domain names",
					"specialUseDomains:",
					"  rfc6762-appendixG: true",
					"# Query type filtering (filter AAAA queries)",
					"filtering:",
					"  queryTypes:",
					"    - AAAA",
				)
				Expect(err).Should(Succeed())
			})

			It("should handle all resolver chain features correctly", func(ctx context.Context) {
				// Test 1: Custom DNS mapping
				By("resolving custom DNS mapping for 'custom.local'", func() {
					msg := util.NewMsgWithQuestion("custom.local.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("custom.local.", A, "10.0.0.1"),
								HaveTTL(BeNumerically(">", 0)),
							))
				})

				// Test 2: Custom DNS with multiple IPs
				By("resolving custom DNS with multiple IPs for 'internal.example.com'", func() {
					msg := util.NewMsgWithQuestion("internal.example.com.", A)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Answer).Should(HaveLen(2))

					ips := make([]string, len(resp.Answer))
					for i, rr := range resp.Answer {
						if a, ok := rr.(*dns.A); ok {
							ips[i] = a.A.String()
						}
					}
					Expect(ips).Should(ContainElements("172.16.0.10", "172.16.0.11"))
				})

				// Test 3: Conditional upstream forwarding
				By("forwarding .local domains to conditional upstream", func() {
					msg := util.NewMsgWithQuestion("server.local.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("server.local.", A, "192.168.1.100"),
								HaveTTL(BeNumerically("<=", 300)),
							))

					msg = util.NewMsgWithQuestion("nas.local.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("nas.local.", A, "192.168.1.50"),
								HaveTTL(BeNumerically("<=", 300)),
							))
				})

				// Test 4: Blocking resolver with denylist
				By("blocking domains from denylist", func() {
					msg := util.NewMsgWithQuestion("ads.example.com.", A)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
					Expect(resp.Answer).Should(BeEmpty())

					msg = util.NewMsgWithQuestion("tracker.analytics.com.", A)
					resp, err = doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
				})

				// Test 5: Blocking with wildcard patterns
				By("blocking domains matching wildcard patterns", func() {
					msg := util.NewMsgWithQuestion("subdomain.malware.com.", A)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
				})

				// Test 6: Allowlist overriding denylist
				By("allowing domains in allowlist even if partially blocked", func() {
					// example.com is in allowlist, so it should not be blocked
					msg := util.NewMsgWithQuestion("example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", A, "93.184.216.34"),
								HaveTTL(BeNumerically("<=", 300)),
							))
				})

				// Test 7: Default upstream resolution
				By("resolving domains via default upstream", func() {
					msg := util.NewMsgWithQuestion("google.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("google.com.", A, "8.8.8.8"),
								HaveTTL(BeNumerically("<=", 300)),
							))
				})

				// Test 8: Caching functionality
				By("caching responses from upstream", func() {
					msg := util.NewMsgWithQuestion("google.com.", A)

					// First query - should hit upstream
					resp1, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					ttl1 := resp1.Answer[0].Header().Ttl

					// Second query - should hit cache with decreased TTL
					resp2, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					ttl2 := resp2.Answer[0].Header().Ttl

					// TTL should be equal or less (depending on timing)
					Expect(ttl2).Should(BeNumerically("<=", ttl1))
				})

				// Test 9: Query type filtering (AAAA)
				By("filtering AAAA queries", func() {
					msg := util.NewMsgWithQuestion("google.com.", AAAA)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					// Should return empty response or NXDOMAIN for filtered types
					Expect(resp.Answer).Should(BeEmpty())
				})

				// Test 10: Special use domain names (.local)
				// Note: .local is handled by conditional upstream in this test,
				// but we can test other special domains
				By("blocking special use domains per RFC6762", func() {
					msg := util.NewMsgWithQuestion("test.invalid.", A)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					// Should be blocked by SUDN resolver
					Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
				})

				// Test 11: Prometheus metrics exposure
				By("exposing Prometheus metrics", func() {
					host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
					Expect(err).Should(Succeed())
					url := "http://" + net.JoinHostPort(host, port) + "/metrics"

					Eventually(func() error {
						resp, err := http.Get(url)
						if err != nil {
							return err
						}
						defer resp.Body.Close()

						if resp.StatusCode != http.StatusOK {
							return fmt.Errorf("expected 200, got %d", resp.StatusCode)
						}

						return nil
					}, "5s", "500ms").Should(Succeed())

					// Verify metrics contain expected data
					Eventually(http.Get).WithArguments(url).Should(
						HaveHTTPBody(And(
							ContainSubstring("blocky_"),
							ContainSubstring("query_total"),
						)),
					)
				})

				// Test 12: API endpoints functionality
				By("serving API endpoints for blocking control", func() {
					host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
					Expect(err).Should(Succeed())
					baseURL := "http://" + net.JoinHostPort(host, port)

					// Check blocking status
					Eventually(http.Get).WithArguments(baseURL + "/api/blocking/status").
						Should(HaveHTTPStatus(http.StatusOK))

					// Disable blocking
					resp, err := http.Get(baseURL + "/api/blocking/disable")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))

					// Verify blocked domain now resolves (blocking disabled)
					msg := util.NewMsgWithQuestion("tracker.analytics.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("tracker.analytics.com.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("<=", 300)),
							))

					// Re-enable blocking
					resp, err = http.Get(baseURL + "/api/blocking/enable")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))

					// Verify domain is blocked again
					msg = util.NewMsgWithQuestion("tracker.analytics.com.", A)
					respDNS, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(respDNS.Rcode).Should(Equal(dns.RcodeNameError))
				})

				// Test 13: Container health check
				By("reporting healthy status", func() {
					Eventually(func(g Gomega) string {
						state, err := blocky.State(ctx)
						g.Expect(err).NotTo(HaveOccurred())

						return state.Health.Status
					}, "2m", "1s").Should(Equal("healthy"))
				})

				// Test 14: Query logging
				By("logging queries to console", func() {
					// Make a query to ensure it gets logged
					msg := util.NewMsgWithQuestion("google.com.", A)
					_, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Check logs contain query information
					Eventually(func() []string {
						logs, _ := getContainerLogs(ctx, blocky)

						return logs
					}, "5s", "500ms").Should(
						ContainElement(And(
							ContainSubstring("google.com"),
							ContainSubstring("question"),
						)),
					)
				})
			})

			It("should maintain resolver chain order and behavior", func(ctx context.Context) {
				// Test that resolvers are executed in the correct order
				// Custom DNS should take precedence over conditional and upstream
				By("prioritizing custom DNS over conditional upstream", func() {
					// Even though internal.example.com matches no conditional,
					// custom DNS should handle it first
					msg := util.NewMsgWithQuestion("internal.example.com.", A)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Should get custom DNS response, not upstream
					Expect(resp.Answer).Should(HaveLen(2))
					ips := make([]string, len(resp.Answer))
					for i, rr := range resp.Answer {
						if a, ok := rr.(*dns.A); ok {
							ips[i] = a.A.String()
						}
					}
					Expect(ips).Should(ContainElements("172.16.0.10", "172.16.0.11"))
				})

				// Blocking should work before caching
				By("blocking domains before they can be cached", func() {
					msg := util.NewMsgWithQuestion("ads.example.com.", A)

					// First query - should be blocked
					resp1, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp1.Rcode).Should(Equal(dns.RcodeNameError))

					// Second query - should still be blocked (from cache)
					resp2, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp2.Rcode).Should(Equal(dns.RcodeNameError))
				})

				// Conditional should take precedence over default upstream
				By("using conditional upstream before default upstream", func() {
					msg := util.NewMsgWithQuestion("server.local.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("server.local.", A, "192.168.1.100"),
								HaveTTL(BeNumerically("<=", 300)),
							))
				})
			})

			It("should handle edge cases in the resolver chain", func(ctx context.Context) {
				// Test NXDOMAIN handling
				By("handling NXDOMAIN responses correctly", func() {
					msg := util.NewMsgWithQuestion("nonexistent.example.com.", A)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					// Should propagate NXDOMAIN from upstream
					Expect(resp.Rcode).Should(Or(
						Equal(dns.RcodeNameError),
						Equal(dns.RcodeSuccess), // or success with empty answer
					))
				})

				// Test case sensitivity
				By("handling case-insensitive domain matching", func() {
					msg := util.NewMsgWithQuestion("CUSTOM.LOCAL.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("CUSTOM.LOCAL.", A, "10.0.0.1"),
								HaveTTL(BeNumerically(">", 0)),
							))
				})

				// Test different query types
				By("handling different DNS query types", func() {
					// A record
					msgA := util.NewMsgWithQuestion("google.com.", A)
					respA, err := doDNSRequest(ctx, blocky, msgA)
					Expect(err).Should(Succeed())
					Expect(respA.Answer).ShouldNot(BeEmpty())

					// AAAA record (should be filtered)
					msgAAAA := util.NewMsgWithQuestion("google.com.", AAAA)
					respAAAA, err := doDNSRequest(ctx, blocky, msgAAAA)
					Expect(err).Should(Succeed())
					Expect(respAAAA.Answer).Should(BeEmpty())
				})
			})
		})
	})
})
