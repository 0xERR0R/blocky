package e2e

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Metrics functional tests", func() {
	var blocky testcontainers.Container
	var err error
	var metricsURL string

	Describe("Metrics", func() {
		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka1", `A google/NOERROR("A 1.2.3.4 123")`)
			Expect(err).Should(Succeed())

			_, err = createHTTPServerContainer(ctx, "httpserver1", tmpDir, "list1.txt", "domain1.com")
			Expect(err).Should(Succeed())

			_, err = createHTTPServerContainer(ctx, "httpserver2", tmpDir, "list2.txt",
				"domain1.com", "domain2", "domain3")
			Expect(err).Should(Succeed())

			_, err = createHTTPServerContainer(ctx, "httpserver2", tmpDir, "list2.txt", "domain1.com", "domain2", "domain3")
			Expect(err).Should(Succeed())

			blocky, err = createBlockyContainer(ctx, tmpDir,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka1",
				"blocking:",
				"  blackLists:",
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
						"blocky_cache_entry_count 0",
						"blocky_cache_hit_count 0",
						"blocky_cache_miss_count 0",
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
							"blocky_cache_entry_count 1",
							"blocky_cache_hit_count 0",
							"blocky_cache_miss_count 1",
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
							"blocky_cache_entry_count 1",
							"blocky_cache_hit_count 1",
							"blocky_cache_miss_count 1",
						))
				})
			})
		})

		When("Lists are loaded", func() {
			It("Should expose list cache sizes per group as metrics", func(ctx context.Context) {
				Eventually(fetchBlockyMetrics).WithArguments(ctx, metricsURL).
					Should(ContainElements(
						"blocky_blacklist_cache{group=\"group1\"} 1",
						"blocky_blacklist_cache{group=\"group2\"} 3",
					))
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
