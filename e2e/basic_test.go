package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Basic functional tests", func() {
	var blocky, moka testcontainers.Container
	var err error

	Describe("Container start", func() {
		BeforeEach(func() {
			moka, err = createDNSMokkaContainer("moka1", `A google/NOERROR("A 1.2.3.4 123")`)

			Expect(err).Should(Succeed())
			DeferCleanup(moka.Terminate)
		})
		When("Minimal configuration is provided", func() {
			BeforeEach(func() {
				blocky, err = createBlockyContainer(tmpDir,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
				)

				Expect(err).Should(Succeed())
				DeferCleanup(blocky.Terminate)
			})
			It("Should start and answer DNS queries", func() {
				msg := util.NewMsgWithQuestion("google.de.", A)

				Expect(doDNSRequest(blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("google.de.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 123)),
						))
			})
			It("should return 'healthy' container status (healthcheck)", func() {
				Eventually(func(g Gomega) string {
					state, err := blocky.State(context.Background())
					g.Expect(err).NotTo(HaveOccurred())

					return state.Health.Status
				}, "2m", "1s").Should(Equal("healthy"))
			})
		})
		Context("http port configuration", func() {
			When("'httpPort' is not defined", func() {
				BeforeEach(func() {
					blocky, err = createBlockyContainer(tmpDir,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka1",
					)

					Expect(err).Should(Succeed())
					DeferCleanup(blocky.Terminate)
				})

				It("should not open http port", func() {
					host, port, err := getContainerHostPort(blocky, "4000/tcp")
					Expect(err).Should(Succeed())

					_, err = http.Get(fmt.Sprintf("http://%s", net.JoinHostPort(host, port)))
					Expect(err).Should(HaveOccurred())
				})
			})
			When("'httpPort' is defined", func() {
				BeforeEach(func() {
					blocky, err = createBlockyContainer(tmpDir,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka1",
						"ports:",
						"  http: 4000",
					)

					Expect(err).Should(Succeed())
					DeferCleanup(blocky.Terminate)
				})
				It("should serve http content", func() {
					host, port, err := getContainerHostPort(blocky, "4000/tcp")
					Expect(err).Should(Succeed())
					url := fmt.Sprintf("http://%s", net.JoinHostPort(host, port))

					By("serve static html content", func() {
						Eventually(http.Get).WithArguments(url).Should(HaveHTTPStatus(http.StatusOK))
					})
					By("serve pprof endpoint", func() {
						Eventually(http.Get).WithArguments(url + "/debug/").Should(HaveHTTPStatus(http.StatusOK))
					})
					By("prometheus endpoint should be disabled", func() {
						Eventually(http.Get).WithArguments(url + "/metrics").Should(HaveHTTPStatus(http.StatusNotFound))
					})
					By("serve DoH endpoint", func() {
						Eventually(http.Get).WithArguments(url +
							"/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB").Should(HaveHTTPStatus(http.StatusOK))
					})
				})
			})
		})
	})
})
