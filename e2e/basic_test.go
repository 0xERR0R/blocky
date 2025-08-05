package e2e

import (
	"context"
	"net"
	"net/http"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Basic functionality", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		// Create a fresh network for each test
		e2eNet = getRandomNetwork(ctx)
	})

	Context("with upstream DNS server", func() {
		BeforeEach(func(ctx context.Context) {
			// Setup mock DNS server that will respond to queries
			_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
			Expect(err).Should(Succeed())
		})

		Describe("Container startup", func() {
			Context("with conflicting port configuration", func() {
				BeforeEach(func(ctx context.Context) {
					// Create blocky with the same port for HTTP and DNS
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

					// Verify container exit status
					state, err := blocky.State(ctx)
					Expect(err).Should(Succeed())
					Expect(state.ExitCode).Should(Equal(1))
				})

				It("fails to start with appropriate error message", func(ctx context.Context) {
					Eventually(blocky.IsRunning, "5s", "2ms").Should(BeFalse())
					Expect(getContainerLogs(ctx, blocky)).
						Should(ContainElement(ContainSubstring("address already in use")))
				})
			})

			Context("with minimal configuration", func() {
				BeforeEach(func(ctx context.Context) {
					// Create blocky with minimal config
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka1",
					)
					Expect(err).Should(Succeed())
				})

				It("starts successfully and resolves DNS queries", func(ctx context.Context) {
					msg := util.NewMsgWithQuestion("google.de.", A)

					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("google.de.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})

				It("reports 'healthy' status via container healthcheck", func(ctx context.Context) {
					Eventually(func(g Gomega) string {
						state, err := blocky.State(ctx)
						g.Expect(err).NotTo(HaveOccurred())

						return state.Health.Status
					}, "2m", "1s").Should(Equal("healthy"))
				})
			})
		})

		Describe("HTTP port configuration", func() {
			Context("when HTTP port is not defined", func() {
				BeforeEach(func(ctx context.Context) {
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka1",
					)
					Expect(err).Should(Succeed())
				})

				It("does not expose HTTP service", func(ctx context.Context) {
					host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
					Expect(err).Should(Succeed())

					_, err = http.Get("http://" + net.JoinHostPort(host, port))
					Expect(err).Should(HaveOccurred())
				})
			})

			Context("when HTTP port is defined", func() {
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

				It("serves HTTP content on configured port", func(ctx context.Context) {
					host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
					Expect(err).Should(Succeed())
					url := "http://" + net.JoinHostPort(host, port)

					By("serving static HTML content", func() {
						Eventually(http.Get).WithArguments(url).Should(HaveHTTPStatus(http.StatusOK))
					})

					By("serving pprof debugging endpoint", func() {
						Eventually(http.Get).WithArguments(url + "/debug/").Should(HaveHTTPStatus(http.StatusOK))
					})

					By("not exposing prometheus metrics by default", func() {
						Eventually(http.Get).WithArguments(url + "/metrics").Should(HaveHTTPStatus(http.StatusNotFound))
					})

					By("serving DNS-over-HTTPS endpoint", func() {
						Eventually(http.Get).WithArguments(url +
							"/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB").Should(HaveHTTPStatus(http.StatusOK))
					})
				})
			})
		})
	})

	Describe("Logging privacy", func() {
		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
			Expect(err).Should(Succeed())
		})

		Context("when privacy mode is enabled", func() {
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

			It("redacts sensitive information from logs", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("google.com.", A)

				// Make two requests to ensure consistent behavior
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

				// Verify logs don't contain sensitive information
				Expect(getContainerLogs(ctx, blocky)).ShouldNot(ContainElement(ContainSubstring("google.com")))
				Expect(getContainerLogs(ctx, blocky)).ShouldNot(ContainElement(ContainSubstring("1.2.3.4")))
			})
		})
	})
})
