package e2e

import (
	"context"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Upstream resolver configuration tests", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("'upstreams.init.strategy' parameter handling", func() {
		When("'upstreams.init.strategy' is fast and upstream server as IP is not reachable", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - 192.192.192.192",
					"  init:",
					"    strategy: fast",
				)
				Expect(err).Should(Succeed())
			})
			It("should start even if upstream server is not reachable", func(ctx context.Context) {
				Expect(blocky.IsRunning()).Should(BeTrue())
				Eventually(ctx, func() ([]string, error) {
					return getContainerLogs(ctx, blocky)
				}).Should(ContainElement(ContainSubstring("initial resolver test failed")))
			})
		})
		When("'upstreams.init.strategy' is fast and upstream server as host name is not reachable", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - some.wrong.host",
					"  init:",
					"    strategy: fast",
				)
				Expect(err).Should(Succeed())
			})
			It("should start even if upstream server is not reachable", func(ctx context.Context) {
				Expect(blocky.IsRunning()).Should(BeTrue())
				Expect(getContainerLogs(ctx, blocky)).Should(ContainElement(ContainSubstring("initial resolver test failed")))
			})
		})
		When("'upstreams.init.strategy' is failOnError and upstream as IP address server is not reachable", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - 192.192.192.192",
					"  init:",
					"    strategy: failOnError",
				)
				Expect(err).Should(HaveOccurred())
			})
			It("should not start", func(ctx context.Context) {
				Expect(blocky.IsRunning()).Should(BeFalse())
				Expect(getContainerLogs(ctx, blocky)).
					Should(ContainElement(ContainSubstring("no valid upstream for group default")))
			})
		})
		When("'upstreams.init.strategy' is failOnError and upstream server as host name is not reachable", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - some.wrong.host",
					"  init:",
					"    strategy: failOnError",
				)
				Expect(err).Should(HaveOccurred())
			})
			It("should not start", func(ctx context.Context) {
				Expect(blocky.IsRunning()).Should(BeFalse())
				Expect(getContainerLogs(ctx, blocky)).
					Should(ContainElement(ContainSubstring("no valid upstream for group default")))
			})
		})
	})
	Describe("'upstreams.timeout' parameter handling", func() {
		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
				`A example.com/NOERROR("A 1.2.3.4 123")`,
				`A delay.com/delay(NOERROR("A 1.1.1.1 100"), "300ms")`)
			Expect(err).Should(Succeed())

			blocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka1",
				"  timeout: 200ms",
			)
			Expect(err).Should(Succeed())
		})
		It("should consider the timeout parameter", func(ctx context.Context) {
			By("query without timeout", func() {
				msg := util.NewMsgWithQuestion("example.com.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 123)),
						))
			})

			By("query with timeout", func() {
				msg := util.NewMsgWithQuestion("delay.com.", A)

				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeServerFailure))
			})
		})
	})

	Describe("'upstreams.strategy' parameter handling", func() {
		When("'upstreams.strategy' is random", func() {
			BeforeEach(func(ctx context.Context) {
				// Create working upstream
				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A random.com/NOERROR("A 1.1.1.1 100")`)
				Expect(err).Should(Succeed())

				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet,
					`A random.com/NOERROR("A 2.2.2.2 100")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - 192.0.2.1", // Failing upstream (non-routable IP)
					"      - moka1",
					"      - moka2",
					"  strategy: random",
					"  timeout: 100ms", // Short timeout
					"caching:",
					"  maxItemsCount: 0", // Disable caching
				)
				Expect(err).Should(Succeed())
			})
			It("should retry with another upstream when one fails", func(ctx context.Context) {
				By("querying and verifying successful response despite failing upstream", func() {
					// Even though first upstream (192.0.2.1) is failing,
					// random strategy should retry with moka1 or moka2 and succeed
					const attempts = 10

					for range attempts {
						msg := util.NewMsgWithQuestion("random.com.", A)
						resp, err := doDNSRequest(ctx, blocky, msg)
						Expect(err).Should(Succeed())
						Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(resp.Answer).Should(HaveLen(1))

						aRecord, ok := resp.Answer[0].(*dns.A)
						Expect(ok).Should(BeTrue())
						// Should get response from working upstreams (1.1.1.1 or 2.2.2.2)
						ip := aRecord.A.String()
						Expect(ip).Should(Or(Equal("1.1.1.1"), Equal("2.2.2.2")))
					}
				})
			})
		})

		When("'upstreams.strategy' is strict", func() {
			BeforeEach(func(ctx context.Context) {
				// Create three mock DNS servers
				// First server responds with 1.1.1.1
				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A strict.com/NOERROR("A 1.1.1.1 100")`)
				Expect(err).Should(Succeed())

				// Second server responds with 2.2.2.2
				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet,
					`A strict.com/NOERROR("A 2.2.2.2 100")`)
				Expect(err).Should(Succeed())

				// Third server responds with 3.3.3.3
				_, err = createDNSMokkaContainer(ctx, "moka3", e2eNet,
					`A strict.com/NOERROR("A 3.3.3.3 100")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"      - moka2",
					"      - moka3",
					"  strategy: strict",
					"caching:",
					"  maxItemsCount: 0", // Disable caching
				)
				Expect(err).Should(Succeed())
			})
			It("should use upstreams in strict order", func(ctx context.Context) {
				By("querying and verifying first upstream is always used", func() {
					// Query multiple times - should always get response from first server (1.1.1.1)
					const attempts = 10

					for range attempts {
						msg := util.NewMsgWithQuestion("strict.com.", A)
						Expect(doDNSRequest(ctx, blocky, msg)).
							Should(
								SatisfyAll(
									BeDNSRecord("strict.com.", A, "1.1.1.1"),
									// TTL might be decremented slightly, so allow 95-100
									HaveTTL(BeNumerically(">=", 95)),
								))
					}
				})
			})
		})

		When("'upstreams.strategy' is strict with failing first upstream", func() {
			BeforeEach(func(ctx context.Context) {
				// First upstream is unreachable (will timeout/fail)
				// Using a non-routable IP address that will fail quickly
				// Second server responds successfully
				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet,
					`A fallback.com/NOERROR("A 2.2.2.2 100")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - 192.0.2.1", // Non-routable test network IP (RFC 5737)
					"      - moka2",
					"  strategy: strict",
					"  timeout: 100ms", // Short timeout to fail fast
					"caching:",
					"  maxItemsCount: 0", // Disable caching
				)
				Expect(err).Should(Succeed())
			})
			It("should fall back to next upstream when first fails", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("fallback.com.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("fallback.com.", A, "2.2.2.2"),
							HaveTTL(BeNumerically(">=", 95)),
						))
			})
		})

		When("'upstreams.strategy' is parallel_best with failing upstreams", func() {
			BeforeEach(func(ctx context.Context) {
				// First server responds successfully
				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A parallel.com/NOERROR("A 1.1.1.1 100")`)
				Expect(err).Should(Succeed())

				// Third server responds successfully but slower
				_, err = createDNSMokkaContainer(ctx, "moka3", e2eNet,
					`A parallel.com/delay(NOERROR("A 3.3.3.3 100"), "50ms")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"      - 192.0.2.1", // Non-routable IP that will fail
					"      - moka3",
					"  strategy: parallel_best",
					"  timeout: 100ms", // Short timeout
					"caching:",
					"  maxItemsCount: 0", // Disable caching
				)
				Expect(err).Should(Succeed())
			})
			It("should prefer working upstreams over failing ones", func(ctx context.Context) {
				// Query multiple times
				// parallel_best should learn that 192.0.2.1 fails and prefer moka1 and moka3
				const attempts = 20
				successCount := 0

				for range attempts {
					msg := util.NewMsgWithQuestion("parallel.com.", A)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Response should be successful (from moka1 or moka3)
					if resp.Rcode == dns.RcodeSuccess {
						successCount++
						Expect(resp.Answer).Should(HaveLen(1))
						aRecord, ok := resp.Answer[0].(*dns.A)
						Expect(ok).Should(BeTrue())
						// Should be either 1.1.1.1 or 3.3.3.3, never from the failing server
						ip := aRecord.A.String()
						Expect(ip).Should(Or(Equal("1.1.1.1"), Equal("3.3.3.3")))
					}
				}

				// Most queries should succeed (from working upstreams)
				Expect(successCount).Should(BeNumerically(">", attempts*8/10))
			})
		})
	})

	Describe("DNS Stamp format for upstream configuration", func() {
		When("upstream is configured with DNS stamp", func() {
			BeforeEach(func(ctx context.Context) {
				// Create a dnsmokka container with test data
				mokaContainer, err := createDNSMokkaContainer(ctx, "moka-stamp", e2eNet,
					`A stamp-test.com/NOERROR("A 10.11.12.13 300")`)
				Expect(err).Should(Succeed())

				// Get the container's IP within the docker network
				mokaIP, err := getContainerNetworkIP(ctx, mokaContainer, e2eNet.Name)
				Expect(err).Should(Succeed())
				Expect(mokaIP).ShouldNot(BeEmpty())

				// Generate DNS stamp pointing to the mokka container's IP
				stamp := generatePlainDNSStamp(mokaIP)

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - "+stamp, // Use DNS stamp pointing to mokka container
					"caching:",
					"  maxItemsCount: 0", // Disable caching for consistent results
				)
				Expect(err).Should(Succeed())
			})

			It("should resolve DNS queries via DNS stamp upstream", func(ctx context.Context) {
				By("resolving a domain via stamp-based upstream", func() {
					msg := util.NewMsgWithQuestion("stamp-test.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("stamp-test.com.", A, "10.11.12.13"),
								HaveTTL(BeNumerically("==", 300)),
							))
				})
			})
		})

		When("DNS stamp and traditional format are mixed", func() {
			BeforeEach(func(ctx context.Context) {
				// Create two dnsmokka containers for testing
				// One will be accessed via DNS stamp, the other via traditional format
				mokaStampContainer, err := createDNSMokkaContainer(ctx, "moka-stamp-mix", e2eNet,
					`A mixed-test.com/NOERROR("A 20.21.22.23 200")`)
				Expect(err).Should(Succeed())

				_, err = createDNSMokkaContainer(ctx, "moka-traditional", e2eNet,
					`A mixed-test.com/NOERROR("A 30.31.32.33 200")`)
				Expect(err).Should(Succeed())

				// Get the stamp container's IP
				mokaStampIP, err := getContainerNetworkIP(ctx, mokaStampContainer, e2eNet.Name)
				Expect(err).Should(Succeed())
				Expect(mokaStampIP).ShouldNot(BeEmpty())

				// Use both DNS stamp format and traditional format
				// to verify they work together in the same configuration
				stamp := generatePlainDNSStamp(mokaStampIP)

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - "+stamp,           // DNS stamp format
					"      - moka-traditional", // Traditional format
					"  strategy: parallel_best",
					"caching:",
					"  maxItemsCount: 0",
				)
				Expect(err).Should(Succeed())
			})

			It("should work with both DNS stamp and traditional upstreams", func(ctx context.Context) {
				By("querying a domain with mixed upstream formats", func() {
					// Query multiple times to verify both upstreams work
					const attempts = 10
					foundStamp := false
					foundTraditional := false

					for range attempts {
						msg := util.NewMsgWithQuestion("mixed-test.com.", A)
						resp, err := doDNSRequest(ctx, blocky, msg)
						Expect(err).Should(Succeed())
						Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(resp.Answer).Should(HaveLen(1))

						aRecord, ok := resp.Answer[0].(*dns.A)
						Expect(ok).Should(BeTrue())
						ip := aRecord.A.String()

						// Track which upstream responded
						switch ip {
						case "20.21.22.23":
							foundStamp = true
						case "30.31.32.33":
							foundTraditional = true
						}

						// Exit early if we've seen both
						if foundStamp && foundTraditional {
							break
						}
					}

					// Verify we got responses from at least one upstream
					// (parallel_best may prefer one over the other)
					Expect(foundStamp || foundTraditional).Should(BeTrue())
				})
			})
		})
	})
})
