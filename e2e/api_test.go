package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("API endpoints", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("Cache flush", func() {
		When("caching is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A cached.example.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka
					ports:
					  http: 4000
					caching:
					  minTime: 5m
					`))
				Expect(err).Should(Succeed())
			})

			It("should clear cache via API", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				baseURL := "http://" + net.JoinHostPort(host, port)

				By("populating cache with a query", func() {
					msg := util.NewMsgWithQuestion("cached.example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("cached.example.com.", A, "1.2.3.4"))
				})

				By("flushing cache via API", func() {
					resp, err := http.Post(baseURL+"/api/cache/flush", "application/json", nil)
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})

				By("verifying cache was cleared (TTL reset to full value)", func() {
					msg := util.NewMsgWithQuestion("cached.example.com.", A)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Answer).Should(HaveLen(1))
					Expect(resp.Answer[0].Header().Ttl).Should(BeNumerically(">=", 295))
				})
			})
		})
	})

	Describe("Query endpoint", func() {
		When("HTTP API is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A example.com/NOERROR("A 93.184.216.34 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka
					ports:
					  http: 4000
					`))
				Expect(err).Should(Succeed())
			})

			It("should resolve queries via API", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				baseURL := "http://" + net.JoinHostPort(host, port)

				By("querying an existing domain", func() {
					reqBody, err := json.Marshal(map[string]string{
						"query": "example.com",
						"type":  "A",
					})
					Expect(err).Should(Succeed())

					resp, err := http.Post(baseURL+"/api/query", "application/json", bytes.NewReader(reqBody))
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))

					body, err := io.ReadAll(resp.Body)
					Expect(err).Should(Succeed())
					Expect(string(body)).Should(ContainSubstring("93.184.216.34"))
				})

				By("querying a non-existing domain", func() {
					reqBody, err := json.Marshal(map[string]string{
						"query": "nonexistent.example.com",
						"type":  "A",
					})
					Expect(err).Should(Succeed())

					resp, err := http.Post(baseURL+"/api/query", "application/json", bytes.NewReader(reqBody))
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})
			})
		})
	})

	Describe("Blocking disable with duration", func() {
		When("blocking is configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A blocked.com/NOERROR("A 5.6.7.8 300")`,
				)
				Expect(err).Should(Succeed())

				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blocked.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka
					ports:
					  http: 4000
					blocking:
					  denylists:
					    ads:
					      - http://httpserver:8080/list.txt
					  clientGroupsBlock:
					    default:
					      - ads
					`))
				Expect(err).Should(Succeed())
			})

			It("should temporarily disable blocking for the specified duration", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				baseURL := "http://" + net.JoinHostPort(host, port)

				By("verifying domain is blocked", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
				})

				By("disabling blocking for 3 seconds", func() {
					resp, err := http.Get(baseURL + "/api/blocking/disable?duration=3s")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})

				By("verifying domain is unblocked", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "5.6.7.8"))
				})

				By("waiting for duration to expire and verifying blocking is re-enabled", func() {
					Eventually(func() *dns.Msg {
						msg := util.NewMsgWithQuestion("blocked.com.", A)
						resp, _ := doDNSRequest(ctx, blocky, msg)

						return resp
					}, "10s", "500ms").Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
				})
			})
		})
	})

	Describe("Blocking disable with groups", func() {
		When("multiple blocking groups are configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A ads-domain.com/NOERROR("A 5.6.7.8 300")`,
					`A malware-domain.com/NOERROR("A 9.8.7.6 300")`,
				)
				Expect(err).Should(Succeed())

				_, err = createHTTPServerContainer(ctx, "httpserver-ads", e2eNet, "ads-list.txt", "ads-domain.com")
				Expect(err).Should(Succeed())

				_, err = createHTTPServerContainer(ctx, "httpserver-malware", e2eNet, "malware-list.txt", "malware-domain.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka
					ports:
					  http: 4000
					blocking:
					  denylists:
					    ads:
					      - http://httpserver-ads:8080/ads-list.txt
					    malware:
					      - http://httpserver-malware:8080/malware-list.txt
					  clientGroupsBlock:
					    default:
					      - ads
					      - malware
					`))
				Expect(err).Should(Succeed())
			})

			It("should disable only the specified group", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				baseURL := "http://" + net.JoinHostPort(host, port)

				By("verifying both groups are blocking", func() {
					msg := util.NewMsgWithQuestion("ads-domain.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("ads-domain.com.", A, "0.0.0.0"))

					msg = util.NewMsgWithQuestion("malware-domain.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("malware-domain.com.", A, "0.0.0.0"))
				})

				By("disabling only the ads group", func() {
					resp, err := http.Get(baseURL + "/api/blocking/disable?groups=ads")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})

				By("verifying ads group is unblocked", func() {
					msg := util.NewMsgWithQuestion("ads-domain.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("ads-domain.com.", A, "5.6.7.8"))
				})

				By("verifying malware group is still blocked", func() {
					msg := util.NewMsgWithQuestion("malware-domain.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("malware-domain.com.", A, "0.0.0.0"))
				})

				By("re-enabling blocking", func() {
					resp, err := http.Get(baseURL + "/api/blocking/enable")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))

					msg := util.NewMsgWithQuestion("ads-domain.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("ads-domain.com.", A, "0.0.0.0"))
				})
			})
		})
	})
})
