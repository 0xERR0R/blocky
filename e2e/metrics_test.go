package e2e

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Metrics functional tests", func() {
	var (
		e2eNet     *testcontainers.DockerNetwork
		blocky     testcontainers.Container
		err        error
		metricsURL string
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("Metrics", func() {
		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
			Expect(err).Should(Succeed())

			_, err = createHTTPServerContainer(ctx, "httpserver1", e2eNet, "list1.txt", "domain1.com")
			Expect(err).Should(Succeed())

			_, err = createHTTPServerContainer(ctx, "httpserver2", e2eNet, "list2.txt",
				"domain1.com", "domain2", "domain3")
			Expect(err).Should(Succeed())

			_, err = createHTTPServerContainer(ctx, "httpserver2", e2eNet, "list2.txt",
				"domain1.com", "domain2", "domain3")
			Expect(err).Should(Succeed())

			blocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka1",
				"blocking:",
				"  denylists:",
				"    group1:",
				"      - http://httpserver1:8080/list1.txt",
				"    group2:",
				"      - http://httpserver2:8080/list2.txt",
				"ports:",
				"  http: 4000",
				"prometheus:",
				"  enable: true",
			)
			Expect(err).Should(Succeed())

			host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
			Expect(err).Should(Succeed())

			metricsURL = fmt.Sprintf("http://%s/metrics", net.JoinHostPort(host, port))
		})
		When("Blocky is started", func() {
			It("Should provide 'blocky_build_info' prometheus metrics", func(ctx context.Context) {
				Eventually(fetchBlockyMetrics).WithArguments(ctx, metricsURL).
					Should(ContainElement(ContainSubstring("blocky_build_info")))
			})

			It("Should provide 'blocky_blocking_enabled' prometheus metrics", func(ctx context.Context) {
				Eventually(fetchBlockyMetrics, "30s", "2ms").WithArguments(ctx, metricsURL).
					Should(ContainElement("blocky_blocking_enabled 1"))
			})
		})

		When("Some query results are cached", func() {
			BeforeEach(func(ctx context.Context) {
				Eventually(fetchBlockyMetrics).WithArguments(ctx, metricsURL).
					Should(ContainElements(
						"blocky_cache_entries 0",
						"blocky_cache_hits_total 0",
						"blocky_cache_misses_total 0",
					))
			})

			It("Should increment cache counts", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("google.de.", A)

				By("first query, should increment the cache miss count and the total count", func() {
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("google.de.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))

					Eventually(fetchBlockyMetrics).WithArguments(ctx, metricsURL).
						Should(ContainElements(
							"blocky_cache_entries 1",
							"blocky_cache_hits_total 0",
							"blocky_cache_misses_total 1",
						))
				})

				By("Same query again, should increment the cache hit count", func() {
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("google.de.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("<=", 123)),
							))

					Eventually(fetchBlockyMetrics).WithArguments(ctx, metricsURL).
						Should(ContainElements(
							"blocky_cache_entries 1",
							"blocky_cache_hits_total 1",
							"blocky_cache_misses_total 1",
						))
				})
			})
		})

		When("Lists are loaded", func() {
			It("Should expose list cache sizes per group as metrics", func(ctx context.Context) {
				Eventually(fetchBlockyMetrics).WithArguments(ctx, metricsURL).
					Should(ContainElements(
						"blocky_denylist_cache_entries{group=\"group1\"} 1",
						"blocky_denylist_cache_entries{group=\"group2\"} 3",
					))
			})
		})
	})

	Describe("Comprehensive metrics test - ALL metrics", func() {
		var (
			testBlocky     testcontainers.Container
			testMetricsURL string
		)

		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
				`A google.com/NOERROR("A 1.2.3.4 123")`,
				`A cached.com/NOERROR("A 5.6.7.8 300")`,
				`A notblocked.com/NOERROR("A 9.10.11.12 123")`,
			)
			Expect(err).Should(Succeed())

			_, err = createHTTPServerContainer(ctx, "denylist", e2eNet, "denylist.txt", "blocked.com", "ads.com")
			Expect(err).Should(Succeed())

			_, err = createHTTPServerContainer(ctx, "allowlist", e2eNet, "allowlist.txt", "allowed.com", "trusted.com")
			Expect(err).Should(Succeed())

			_, err = createHTTPServerContainer(ctx, "badlist", e2eNet, "badlist.txt", "bad.com")
			Expect(err).Should(Succeed())

			testBlocky, err = createBlockyContainer(ctx, e2eNet,
				"log:",
				"  level: warn",
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka1",
				"blocking:",
				"  denylists:",
				"    ads:",
				"      - http://denylist:8080/denylist.txt",
				"    malware:",
				"      - http://badlist:8080/badlist.txt",
				"  allowlists:",
				"    trusted:",
				"      - http://allowlist:8080/allowlist.txt",
				"  clientGroupsBlock:",
				"    default:",
				"      - ads",
				"ports:",
				"  http: 4000",
				"prometheus:",
				"  enable: true",
				"caching:",
				"  prefetching: false",
			)
			Expect(err).Should(Succeed())

			host, port, err := getContainerHostPort(ctx, testBlocky, "4000/tcp")
			Expect(err).Should(Succeed())

			testMetricsURL = fmt.Sprintf("http://%s/metrics", net.JoinHostPort(host, port))
		})

		It("Should have ALL expected metrics after various operations", func(ctx context.Context) {
			metricsList := fetchAllBlockyMetrics(ctx, testMetricsURL)

			By("verifying build info metric exists", func() {
				Expect(metricsList).Should(ContainElement(ContainSubstring("blocky_build_info")))
			})

			By("verifying blocking enabled metric", func() {
				Expect(metricsList).Should(ContainElement("blocky_blocking_enabled 1"))
			})

			By("verifying denylist cache entries", func() {
				Expect(metricsList).Should(ContainElement(MatchRegexp(`blocky_denylist_cache_entries\{group="ads"\} 2`)))
				Expect(metricsList).Should(ContainElement(MatchRegexp(`blocky_denylist_cache_entries\{group="malware"\} 1`)))
			})

			By("verifying allowlist cache entries", func() {
				Expect(metricsList).Should(ContainElement(MatchRegexp(`blocky_allowlist_cache_entries\{group="trusted"\} 2`)))
			})

			By("verifying last list refresh timestamp", func() {
				Expect(metricsList).Should(ContainElement(MatchRegexp(`blocky_last_list_group_refresh_timestamp_seconds \d+`)))
			})

			By("performing DNS queries to trigger query/response metrics", func() {
				msg := util.NewMsgWithQuestion("google.com.", A)
				_, err := doDNSRequest(ctx, testBlocky, msg)
				Expect(err).Should(Succeed())

				msg = util.NewMsgWithQuestion("cached.com.", A)
				_, err = doDNSRequest(ctx, testBlocky, msg)
				Expect(err).Should(Succeed())

				msg = util.NewMsgWithQuestion("cached.com.", A)
				_, err = doDNSRequest(ctx, testBlocky, msg)
				Expect(err).Should(Succeed())

				msg = util.NewMsgWithQuestion("blocked.com.", A)
				_, err = doDNSRequest(ctx, testBlocky, msg)
				Expect(err).Should(Succeed())

				msg = util.NewMsgWithQuestion("allowed.com.", A)
				_, err = doDNSRequest(ctx, testBlocky, msg)
				Expect(err).Should(Succeed())
			})

			Eventually(func(g Gomega) {
				metrics := fetchAllBlockyMetrics(ctx, testMetricsURL)
				g.Expect(metrics).Should(SatisfyAll(
					ContainElement(MatchRegexp(`blocky_query_total\{[^}]*type="A"[^}]*\} \d+`)),
					ContainElement(MatchRegexp(`blocky_response_total\{[^}]*\} \d+`)),
					ContainElement(MatchRegexp(`blocky_request_duration_seconds_bucket\{[^}]*\}`)),
					ContainElement(MatchRegexp(`blocky_request_duration_seconds_sum\{[^}]*\} [\d.]+`)),
					ContainElement(MatchRegexp(`blocky_request_duration_seconds_count\{[^}]*\} \d+`)),
				))
			}, "30s", "2s").Should(Succeed())

			By("verifying cache metrics", func() {
				metrics := fetchAllBlockyMetrics(ctx, testMetricsURL)
				Expect(metrics).Should(ContainElement(MatchRegexp(`blocky_cache_entries \d+`)))
				Expect(metrics).Should(ContainElement(MatchRegexp(`blocky_cache_hits_total \d+`)))
				Expect(metrics).Should(ContainElement(MatchRegexp(`blocky_cache_misses_total \d+`)))
			})
		})
	})

	Describe("Allowlist metrics", func() {
		var (
			testBlocky     testcontainers.Container
			testMetricsURL string
		)

		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A test.com/NOERROR("A 1.2.3.4 123")`)
			Expect(err).Should(Succeed())

			_, err = createHTTPServerContainer(ctx, "allowlist1", e2eNet, "allowlist1.txt", "allowed1.com")
			Expect(err).Should(Succeed())

			_, err = createHTTPServerContainer(ctx, "allowlist2", e2eNet, "allowlist2.txt", "allowed2.com", "allowed3.com")
			Expect(err).Should(Succeed())

			testBlocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka1",
				"blocking:",
				"  allowlists:",
				"    group1:",
				"      - http://allowlist1:8080/allowlist1.txt",
				"    group2:",
				"      - http://allowlist2:8080/allowlist2.txt",
				"ports:",
				"  http: 4000",
				"prometheus:",
				"  enable: true",
			)
			Expect(err).Should(Succeed())

			host, port, err := getContainerHostPort(ctx, testBlocky, "4000/tcp")
			Expect(err).Should(Succeed())

			testMetricsURL = fmt.Sprintf("http://%s/metrics", net.JoinHostPort(host, port))
		})

		It("Should expose allowlist cache sizes per group as metrics", func(ctx context.Context) {
			Eventually(func(g Gomega) {
				metrics := fetchAllBlockyMetrics(ctx, testMetricsURL)
				g.Expect(metrics).Should(ContainElements(
					MatchRegexp(`blocky_allowlist_cache_entries\{group="group1"\} 1`),
					MatchRegexp(`blocky_allowlist_cache_entries\{group="group2"\} 2`),
				))
			}, "30s", "2s").Should(Succeed())
		})
	})

	Describe("Failed download metrics", func() {
		var (
			testBlocky     testcontainers.Container
			testMetricsURL string
		)

		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A test.com/NOERROR("A 1.2.3.4 123")`)
			Expect(err).Should(Succeed())

			testBlocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka1",
				"blocking:",
				"  denylists:",
				"    ads:",
				"      - http://nonexistent-host-that-does-not-exist.example:8080/list.txt",
				"  loading:",
				"    strategy: blocking",
				"ports:",
				"  http: 4000",
				"prometheus:",
				"  enable: true",
			)
			Expect(err).Should(Succeed())

			host, port, err := getContainerHostPort(ctx, testBlocky, "4000/tcp")
			Expect(err).Should(Succeed())

			testMetricsURL = fmt.Sprintf("http://%s/metrics", net.JoinHostPort(host, port))
		})

		It("Should increment failed downloads counter when list download fails", func(ctx context.Context) {
			Eventually(func(g Gomega) {
				metrics := fetchAllBlockyMetrics(ctx, testMetricsURL)
				g.Expect(metrics).Should(ContainElement(MatchRegexp(`blocky_failed_downloads_total \d+`)))
			}, "30s", "2s").Should(Succeed())
		})
	})

	Describe("Query and error metrics", func() {
		var (
			testBlocky     testcontainers.Container
			testMetricsURL string
		)

		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
				`A google.com/NOERROR("A 1.2.3.4 123")`,
				`A cached.com/NOERROR("A 5.6.7.8 300")`,
			)
			Expect(err).Should(Succeed())

			testBlocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka1",
				"ports:",
				"  http: 4000",
				"prometheus:",
				"  enable: true",
				"caching:",
				"  minTime: 5s",
			)
			Expect(err).Should(Succeed())

			host, port, err := getContainerHostPort(ctx, testBlocky, "4000/tcp")
			Expect(err).Should(Succeed())

			testMetricsURL = fmt.Sprintf("http://%s/metrics", net.JoinHostPort(host, port))
		})

		It("Should track queries, responses, errors, and request duration", func(ctx context.Context) {
			By("performing successful queries", func() {
				msg := util.NewMsgWithQuestion("google.com.", A)
				_, err := doDNSRequest(ctx, testBlocky, msg)
				Expect(err).Should(Succeed())

				msg = util.NewMsgWithQuestion("cached.com.", A)
				_, err = doDNSRequest(ctx, testBlocky, msg)
				Expect(err).Should(Succeed())

				msg = util.NewMsgWithQuestion("cached.com.", A)
				_, err = doDNSRequest(ctx, testBlocky, msg)
				Expect(err).Should(Succeed())
			})

			Eventually(func(g Gomega) {
				metrics := fetchAllBlockyMetrics(ctx, testMetricsURL)
				g.Expect(metrics).Should(SatisfyAll(
					ContainElement(MatchRegexp(`blocky_query_total\{[^}]*type="A"[^}]*\} 3`)),
					ContainElement(MatchRegexp(`blocky_response_total\{[^}]*\} \d+`)),
					ContainElement(MatchRegexp(`blocky_cache_hits_total 1`)),
					ContainElement(MatchRegexp(`blocky_cache_misses_total 2`)),
					ContainElement(MatchRegexp(`blocky_cache_entries 2`)),
					ContainElement(MatchRegexp(`blocky_request_duration_seconds_bucket\{[^}]*\}`)),
					ContainElement(MatchRegexp(`blocky_request_duration_seconds_sum\{[^}]*\} [\d.]+`)),
					ContainElement(MatchRegexp(`blocky_request_duration_seconds_count\{[^}]*\} \d+`)),
				))
			}, "30s", "2s").Should(Succeed())
		})
	})

	Describe("Prefetch metrics", func() {
		var (
			testBlocky     testcontainers.Container
			testMetricsURL string
		)

		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
				`A prefetch.com/NOERROR("A 1.2.3.4 1")`,
			)
			Expect(err).Should(Succeed())

			testBlocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka1",
				"ports:",
				"  http: 4000",
				"prometheus:",
				"  enable: true",
				"caching:",
				"  minTime: 1s",
				"  maxTime: 10s",
				"  prefetching: true",
				"  prefetchExpires: 5m",
				"  prefetchThreshold: 3",
			)
			Expect(err).Should(Succeed())

			host, port, err := getContainerHostPort(ctx, testBlocky, "4000/tcp")
			Expect(err).Should(Succeed())

			testMetricsURL = fmt.Sprintf("http://%s/metrics", net.JoinHostPort(host, port))
		})

		It("Should track prefetch metrics after TTL expires", func(ctx context.Context) {
			By("querying same domain multiple times to trigger prefetching", func() {
				for range 5 {
					msg := util.NewMsgWithQuestion("prefetch.com.", A)
					_, err := doDNSRequest(ctx, testBlocky, msg)
					Expect(err).Should(Succeed())
				}
			})

			By("waiting for TTL to expire and prefetch to happen", func() {
				time.Sleep(2 * time.Second)
			})

			By("querying again to see prefetch results", func() {
				msg := util.NewMsgWithQuestion("prefetch.com.", A)
				_, err := doDNSRequest(ctx, testBlocky, msg)
				Expect(err).Should(Succeed())
			})

			By("verifying prefetch metrics are incremented", func() {
				Eventually(func(g Gomega) {
					metrics := fetchAllBlockyMetrics(ctx, testMetricsURL)
					
					g.Expect(metrics).Should(SatisfyAll(
						ContainElement(MatchRegexp(`blocky_prefetches_total \d+`)),
						ContainElement(MatchRegexp(`blocky_prefetch_hits_total \d+`)),
						ContainElement(MatchRegexp(`blocky_prefetch_domain_name_cache_entries [1-9]`)),
					))
					g.Expect(metrics).Should(ContainElement(MatchRegexp(`blocky_prefetches_total [1-9]`)))
				}, "10s", "1s").Should(Succeed())
			})
		})
	})
})

func fetchBlockyMetrics(ctx context.Context, url string) ([]string, error) {
	var metrics []string

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer r.Body.Close()

	scanner := bufio.NewScanner(r.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "blocky_") {
			metrics = append(metrics, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return metrics, nil
}

func fetchAllBlockyMetrics(ctx context.Context, url string) []string {
	metrics, err := fetchBlockyMetrics(ctx, url)
	Expect(err).Should(Succeed())

	return metrics
}
