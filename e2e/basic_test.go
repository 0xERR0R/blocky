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
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("Container start", func() {
		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
			Expect(err).Should(Succeed())
		})
		When("wrong port configuration is provided", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"ports:",
					"  http: 4000",
					"  dns: 4000",
				)
				Expect(err).Should(HaveOccurred())

				// check container exit status
				state, err := blocky.State(ctx)
				Expect(err).Should(Succeed())
				Expect(state.ExitCode).Should(Equal(1))
			})
			It("should fail to start", func(ctx context.Context) {
				Eventually(blocky.IsRunning, "5s", "2ms").Should(BeFalse())

				Expect(getContainerLogs(ctx, blocky)).
					Should(ContainElement(ContainSubstring("address already in use")))
			})
		})
		When("Minimal configuration is provided", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
				)

				Expect(err).Should(Succeed())
			})
			It("Should start and answer DNS queries", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("google.de.", A)

				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("google.de.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 123)),
						))
			})
			It("should return 'healthy' container status (healthcheck)", func(ctx context.Context) {
				Eventually(func(g Gomega) string {
					state, err := blocky.State(ctx)
					g.Expect(err).NotTo(HaveOccurred())

					return state.Health.Status
				}, "2m", "1s").Should(Equal("healthy"))
			})
		})
		Context("http port configuration", func() {
			When("'httpPort' is not defined", func() {
				BeforeEach(func(ctx context.Context) {
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka1",
					)

					Expect(err).Should(Succeed())
				})

				It("should not open http port", func(ctx context.Context) {
					host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
					Expect(err).Should(Succeed())

					_, err = http.Get(fmt.Sprintf("http://%s", net.JoinHostPort(host, port)))
					Expect(err).Should(HaveOccurred())
				})
			})
			When("'httpPort' is defined", func() {
				BeforeEach(func(ctx context.Context) {
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka1",
						"ports:",
						"  http: 4000",
					)

					Expect(err).Should(Succeed())
				})
				It("should serve http content", func(ctx context.Context) {
					host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
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

	Describe("Logging", func() {
		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
			Expect(err).Should(Succeed())
		})
		When("log privacy is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"log:",
					"  level: trace",
					"  privacy: true",
				)
				Expect(err).Should(Succeed())
			})
			It("should not log answers and questions", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("google.com.", A)

				// do 2 requests

				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("google.com.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 123)),
						))

				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("google.com.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("<=", 123)),
						))

				Expect(getContainerLogs(ctx, blocky)).ShouldNot(ContainElement(ContainSubstring("google.com")))
				Expect(getContainerLogs(ctx, blocky)).ShouldNot(ContainElement(ContainSubstring("1.2.3.4")))
			})
		})
	})
})
