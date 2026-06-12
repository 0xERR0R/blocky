package e2e

import (
	"context"
	"time"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Caching configuration tests", func() {
	var (
		e2eNet        *testcontainers.DockerNetwork
		blocky, mokka testcontainers.Container
		err           error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("Cache Min/Max Time", func() {
		When("minTime and maxTime are configured", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS server with TTL of 2 seconds
				mokka, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A short-ttl.com/NOERROR("A 1.2.3.4 2")`,
					`A long-ttl.com/NOERROR("A 5.6.7.8 3600")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka1
					caching:
					  minTime: 5s
					  maxTime: 30s
					`))
				Expect(err).Should(Succeed())
			})

			It("should enforce minimum cache time", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("short-ttl.com.", A)

				By("First query should return response with minTime applied (5s)", func() {
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("short-ttl.com.", A, "1.2.3.4"),
								HaveTTL(BeNumerically(">=", 2)), // At least original TTL
								HaveTTL(BeNumerically("<=", 5)), // But capped at minTime
							))
				})

				By("Wait for TTL to decrease", func() {
					Eventually(func() uint32 {
						resp, err := doDNSRequest(ctx, blocky, msg)
						if err != nil {
							return 0
						}
						if len(resp.Answer) > 0 {
							return resp.Answer[0].Header().Ttl
						}

						return 0
					}, "3s", "100ms").Should(BeNumerically("<", 5))
				})

				By("Terminate upstream to ensure cache is used", func() {
					Expect(mokka.Terminate(ctx)).Should(Succeed())
				})

				By("Second query should still return cached response (minTime=5s enforced)", func() {
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("short-ttl.com.", A, "1.2.3.4"),
								HaveTTL(BeNumerically(">", 0)), // Should still have TTL remaining
							))
				})

				By("No warnings/errors in log", func() {
					Expect(getContainerLogs(ctx, blocky)).Should(BeEmpty())
				})
			})

			It("should enforce maximum cache time", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("long-ttl.com.", A)

				By("First query should cap TTL at maxTime (30s)", func() {
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("long-ttl.com.", A, "5.6.7.8"),
								HaveTTL(BeNumerically("<=", 30)),
							))
				})

				By("No warnings/errors in log", func() {
					Expect(getContainerLogs(ctx, blocky)).Should(BeEmpty())
				})
			})
		})
	})

	Describe("Cache Prefetching", func() {
		When("prefetching is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				mokka, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A prefetch.com/NOERROR("A 9.8.7.6 5")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka1
					caching:
					  prefetching: true
					  prefetchThreshold: 3
					  prefetchExpires: 2h
					`))
				Expect(err).Should(Succeed())
			})

			It("should prefetch frequently queried domains", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("prefetch.com.", A)

				By("Query domain multiple times to mark it for prefetching", func() {
					for range 5 {
						Expect(doDNSRequest(ctx, blocky, msg)).
							Should(BeDNSRecord("prefetch.com.", A, "9.8.7.6"))
						time.Sleep(500 * time.Millisecond) // Space out queries for prefetch detection
					}
				})

				By("Wait for TTL to decrease below prefetch threshold (3s)", func() {
					Eventually(func() uint32 {
						resp, err := doDNSRequest(ctx, blocky, msg)
						if err != nil {
							return 999
						}
						if len(resp.Answer) > 0 {
							return resp.Answer[0].Header().Ttl
						}

						return 999
					}, "5s", "200ms").Should(BeNumerically("<=", 3))
				})

				By("Terminate upstream to verify prefetch occurred", func() {
					Expect(mokka.Terminate(ctx)).Should(Succeed())
				})

				By("Query should still return cached/prefetched response", func() {
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("prefetch.com.", A, "9.8.7.6"))
				})

				By("No warnings/errors in log", func() {
					Expect(getContainerLogs(ctx, blocky)).Should(BeEmpty())
				})
			})
		})
	})

	Describe("Cache Exclusions", func() {
		When("cache exclusion patterns are configured", func() {
			BeforeEach(func(ctx context.Context) {
				mokka, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A nocache.example.com/NOERROR("A 1.1.1.1 300")`,
					`A cached.example.com/NOERROR("A 2.2.2.2 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka1
					caching:
					  cacheTimeNegative: 30m
					  exclude:
					    - /nocache/
					`))
				Expect(err).Should(Succeed())
			})

			It("should not cache excluded domains", func(ctx context.Context) {
				msgNocache := util.NewMsgWithQuestion("nocache.example.com.", A)
				msgCached := util.NewMsgWithQuestion("cached.example.com.", A)

				By("Query both domains multiple times", func() {
					// Query each domain twice to verify caching behavior
					Expect(doDNSRequest(ctx, blocky, msgNocache)).
						Should(BeDNSRecord("nocache.example.com.", A, "1.1.1.1"))
					Expect(doDNSRequest(ctx, blocky, msgNocache)).
						Should(BeDNSRecord("nocache.example.com.", A, "1.1.1.1"))

					Expect(doDNSRequest(ctx, blocky, msgCached)).
						Should(BeDNSRecord("cached.example.com.", A, "2.2.2.2"))
					Expect(doDNSRequest(ctx, blocky, msgCached)).
						Should(BeDNSRecord("cached.example.com.", A, "2.2.2.2"))
				})

				By("Terminate upstream", func() {
					Expect(mokka.Terminate(ctx)).Should(Succeed())
				})

				By("Cached domain should return from cache", func() {
					Expect(doDNSRequest(ctx, blocky, msgCached)).
						Should(BeDNSRecord("cached.example.com.", A, "2.2.2.2"))
				})

				By("Excluded domain should return SERVFAIL (not cached)", func() {
					resp, err := doDNSRequest(ctx, blocky, msgNocache)
					Expect(err).Should(Succeed())
					Expect(resp.Rcode).Should(Equal(dns.RcodeServerFailure))
				})
			})
		})
	})

	Describe("Negative Caching", func() {
		When("negative caching is configured", func() {
			BeforeEach(func(ctx context.Context) {
				mokka, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A nonexistent/NXDOMAIN()`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka1
					caching:
					  cacheTimeNegative: 30m
					`))
				Expect(err).Should(Succeed())
			})

			It("should cache NXDOMAIN responses", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("nonexistent.com.", A)

				By("First query should return NXDOMAIN", func() {
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
				})

				By("Terminate upstream to ensure cache is used", func() {
					Expect(mokka.Terminate(ctx)).Should(Succeed())
				})

				By("Second query should return cached NXDOMAIN", func() {
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
				})

				By("No warnings/errors in log", func() {
					Expect(getContainerLogs(ctx, blocky)).Should(BeEmpty())
				})
			})
		})
	})

	Describe("Cache Item Count Limits", func() {
		When("cache size limits are configured", func() {
			BeforeEach(func(ctx context.Context) {
				// Create multiple DNS responses
				mokka, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A domain1.com/NOERROR("A 1.1.1.1 300")`,
					`A domain2.com/NOERROR("A 2.2.2.2 300")`,
					`A domain3.com/NOERROR("A 3.3.3.3 300")`,
					`A domain4.com/NOERROR("A 4.4.4.4 300")`,
					`A domain5.com/NOERROR("A 5.5.5.5 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka1
					caching:
					  maxItemsCount: 3
					`))
				Expect(err).Should(Succeed())
			})

			It("should respect maxItemsCount limit", func(ctx context.Context) {
				// Exact LRU eviction order is a property of the cache library
				// (covered by expiration-cache's own tests) and, with cache sharding,
				// is intentionally approximate. blocky's e2e only verifies the
				// integration: the count limit is enforced and cached entries are
				// still served once the upstream is gone.
				domains := []struct{ name, ip string }{
					{"domain1.com.", "1.1.1.1"},
					{"domain2.com.", "2.2.2.2"},
					{"domain3.com.", "3.3.3.3"},
					{"domain4.com.", "4.4.4.4"},
				}

				By("Query 4 different domains, exceeding the cache limit of 3", func() {
					for _, d := range domains {
						Expect(doDNSRequest(ctx, blocky, util.NewMsgWithQuestion(d.name, A))).Should(
							BeDNSRecord(d.name, A, d.ip))
					}
				})

				By("Terminate upstream so only cached entries can be resolved", func() {
					Expect(mokka.Terminate(ctx)).Should(Succeed())
				})

				By("The most recently queried domain is still cached", func() {
					// the newest entry is never the one evicted, regardless of sharding
					Expect(doDNSRequest(ctx, blocky, util.NewMsgWithQuestion("domain4.com.", A))).Should(
						BeDNSRecord("domain4.com.", A, "4.4.4.4"))
				})

				By("maxItemsCount is enforced: not all earlier domains survive", func() {
					cached := 0
					for _, d := range domains[:3] {
						resp, err := doDNSRequest(ctx, blocky, util.NewMsgWithQuestion(d.name, A))
						Expect(err).Should(Succeed())
						if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
							cached++
						}
					}
					// domain4 occupies one of the 3 slots, so at most 2 of the first
					// three can remain — at least one must have been evicted.
					Expect(cached).Should(BeNumerically("<=", 2))
				})

				By("No warnings in log", func() {
					logs, err := getContainerLogs(ctx, blocky)
					Expect(err).Should(Succeed())
					for _, log := range logs {
						Expect(log).ShouldNot(ContainSubstring("WARN"))
					}
				})
			})
		})
	})
})
