package e2e

import (
	"context"
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

var _ = Describe("Config Reload", Label("e2e"), func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	Describe("SIGHUP reload", func() {
		When("config changes to valid config", func() {
			BeforeEach(func(ctx context.Context) {
				e2eNet = getRandomNetwork(ctx)

				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A example.com/NOERROR("A 1.2.3.4 123")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"ports:",
					"  http: 4000",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - |",
					"        example.com",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("should apply new config after SIGHUP", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)

				By("Verify example.com is initially blocked", func() {
					Eventually(doDNSRequest, "5s", "100ms").
						WithArguments(ctx, blocky, msg).
						Should(BeDNSRecord("example.com.", A, "0.0.0.0"))
				})

				By("Modify config to remove blocking", func() {
					newConfig := strings.Join([]string{
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka1",
						"ports:",
						"  http: 4000",
					}, "\n")
					Expect(modifyContainerFile(ctx, blocky, "/app/config.yml", newConfig)).Should(Succeed())
				})

				By("Send SIGHUP", func() {
					Expect(sendSignal(ctx, blocky, "HUP")).Should(Succeed())
				})

				By("Verify example.com is now resolved", func() {
					Eventually(doDNSRequest, "10s", "500ms").
						WithArguments(ctx, blocky, msg).
						Should(BeDNSRecord("example.com.", A, "1.2.3.4"))
				})
			})
		})

		When("config is replaced with invalid YAML", func() {
			BeforeEach(func(ctx context.Context) {
				e2eNet = getRandomNetwork(ctx)

				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A example.com/NOERROR("A 1.2.3.4 123")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"ports:",
					"  http: 4000",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - |",
					"        example.com",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("should keep old config active", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)

				By("Verify initially blocked", func() {
					Eventually(doDNSRequest, "5s", "100ms").
						WithArguments(ctx, blocky, msg).
						Should(BeDNSRecord("example.com.", A, "0.0.0.0"))
				})

				By("Replace config with invalid YAML", func() {
					Expect(modifyContainerFile(ctx, blocky, "/app/config.yml", "invalid: [yaml: broken")).
						Should(Succeed())
				})

				By("Send SIGHUP", func() {
					// Ignore error: blocky may still return non-zero if reload fails internally
					_ = sendSignal(ctx, blocky, "HUP")
				})

				By("Verify DNS still works with old config after brief pause", func() {
					time.Sleep(3 * time.Second)
					Consistently(doDNSRequest, "3s", "500ms").
						WithArguments(ctx, blocky, msg).
						Should(BeDNSRecord("example.com.", A, "0.0.0.0"))
				})
			})
		})
	})

	Describe("API-triggered reload", func() {
		When("config changes to valid config", func() {
			BeforeEach(func(ctx context.Context) {
				e2eNet = getRandomNetwork(ctx)

				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet,
					`A example.com/NOERROR("A 1.2.3.4 123")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"ports:",
					"  http: 4000",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - |",
					"        example.com",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("should apply new config after POST /api/config/reload", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)

				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				baseURL := "http://" + net.JoinHostPort(host, port)

				By("Verify example.com is initially blocked", func() {
					Eventually(doDNSRequest, "5s", "100ms").
						WithArguments(ctx, blocky, msg).
						Should(BeDNSRecord("example.com.", A, "0.0.0.0"))
				})

				By("Modify config to remove blocking", func() {
					newConfig := strings.Join([]string{
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka1",
						"ports:",
						"  http: 4000",
					}, "\n")
					Expect(modifyContainerFile(ctx, blocky, "/app/config.yml", newConfig)).Should(Succeed())
				})

				By("Trigger reload via API", func() {
					resp, err := http.Post(baseURL+"/api/config/reload", "application/json", nil)
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})

				By("Verify example.com is now resolved", func() {
					Eventually(doDNSRequest, "10s", "500ms").
						WithArguments(ctx, blocky, msg).
						Should(BeDNSRecord("example.com.", A, "1.2.3.4"))
				})
			})
		})
	})
})
