package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Statistics functional tests", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("Stats endpoint", func() {
		When("statistics are enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A google.com/NOERROR("A 1.2.3.4 300")`)
				Expect(err).Should(Succeed())

				_, err = createHTTPServerContainer(ctx, "httpserver1", e2eNet, "list1.txt", "ads.example.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka1
					blocking:
					  denylists:
					    ads:
					      - http://httpserver1:8080/list1.txt
					  clientGroupsBlock:
					    default:
					      - ads
					caching:
					  minTime: 5m
					ports:
					  http: 4000
					statistics:
					  enable: true
					`))
				Expect(err).Should(Succeed())
			})

			It("aggregates queries and serves them as JSON", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				statsURL := "http://" + net.JoinHostPort(host, port) + "/api/stats"

				By("driving three distinct query outcomes", func() {
					// 1. forwarded (resolved upstream)
					Expect(doDNSRequest(ctx, blocky, util.NewMsgWithQuestion("google.com.", A))).
						Should(BeDNSRecord("google.com.", A, "1.2.3.4"))
					// 2. cached (same query again)
					Expect(doDNSRequest(ctx, blocky, util.NewMsgWithQuestion("google.com.", A))).
						Should(BeDNSRecord("google.com.", A, "1.2.3.4"))
					// 3. blocked (denylisted domain)
					_, err := doDNSRequest(ctx, blocky, util.NewMsgWithQuestion("ads.example.com.", A))
					Expect(err).Should(Succeed())
				})

				By("reading /api/stats (collection is async, so poll)", func() {
					Eventually(func(g Gomega) {
						res := fetchStats(ctx, g, statsURL)
						g.Expect(res.Summary.Queries).Should(BeNumerically("==", 3))
						g.Expect(res.Summary.Blocked).Should(BeNumerically("==", 1))
						g.Expect(res.Summary.Cached).Should(BeNumerically("==", 1))
						g.Expect(res.Summary.Forwarded).Should(BeNumerically("==", 1))
						g.Expect(res.ByResponseType).Should(HaveKey("BLOCKED"))
						g.Expect(res.ByResponseType).Should(HaveKey("CACHED"))
						g.Expect(res.ByResponseType).Should(HaveKey("RESOLVED"))
						g.Expect(namesIn(res.TopDomains)).Should(ContainElement("google.com"))
						g.Expect(namesIn(res.TopBlockedDomains)).Should(ContainElement("ads.example.com"))
					}, "30s", "500ms").Should(Succeed())
				})
			})
		})

		When("statistics are disabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A google.com/NOERROR("A 1.2.3.4 300")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka1
					ports:
					  http: 4000
					`))
				Expect(err).Should(Succeed())
			})

			It("returns 503 from /api/stats", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())

				req, err := http.NewRequestWithContext(ctx, http.MethodGet,
					"http://"+net.JoinHostPort(host, port)+"/api/stats", nil)
				Expect(err).Should(Succeed())

				resp, err := http.DefaultClient.Do(req)
				Expect(err).Should(Succeed())
				defer resp.Body.Close()
				Expect(resp.StatusCode).Should(Equal(http.StatusServiceUnavailable))
			})
		})
	})
})

type e2eStats struct {
	Summary struct {
		Queries   int `json:"queries"`
		Blocked   int `json:"blocked"`
		Cached    int `json:"cached"`
		Forwarded int `json:"forwarded"`
	} `json:"summary"`
	ByResponseType    map[string]int `json:"byResponseType"`
	TopDomains        []e2eNameCount `json:"topDomains"`
	TopBlockedDomains []e2eNameCount `json:"topBlockedDomains"`
}

type e2eNameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func fetchStats(ctx context.Context, g Gomega, url string) e2eStats {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	g.Expect(err).Should(Succeed())

	resp, err := http.DefaultClient.Do(req)
	g.Expect(err).Should(Succeed())
	defer resp.Body.Close()
	g.Expect(resp.StatusCode).Should(Equal(http.StatusOK))

	body, err := io.ReadAll(resp.Body)
	g.Expect(err).Should(Succeed())

	var s e2eStats
	g.Expect(json.Unmarshal(body, &s)).Should(Succeed())

	return s
}

func namesIn(in []e2eNameCount) []string {
	out := make([]string, 0, len(in))
	for _, nc := range in {
		out = append(out, nc.Name)
	}

	return out
}
