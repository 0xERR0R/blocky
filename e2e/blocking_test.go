package e2e

import (
	"context"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("External lists and query blocking", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
		Expect(err).Should(Succeed())
	})
	Describe("List download on startup", func() {
		When("external denylist ist not available", func() {
			Context("loading.strategy = blocking", func() {
				BeforeEach(func(ctx context.Context) {
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"log:",
						"  level: warn",
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka",
						"blocking:",
						"  loading:",
						"    strategy: blocking",
						"  denylists:",
						"    ads:",
						"      - http://wrong.domain.url/list.txt",
						"  clientGroupsBlock:",
						"    default:",
						"      - ads",
					)
					Expect(err).Should(Succeed())
				})

				It("should start with warning in log work without errors", func(ctx context.Context) {
					msg := util.NewMsgWithQuestion("google.com.", A)

					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("google.com.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))

					Expect(getContainerLogs(ctx, blocky)).Should(ContainElement(ContainSubstring("cannot open source: ")))
				})
			})
			Context("loading.strategy = failOnError", func() {
				BeforeEach(func(ctx context.Context) {
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"log:",
						"  level: warn",
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka",
						"blocking:",
						"  loading:",
						"    strategy: failOnError",
						"  denylists:",
						"    ads:",
						"      - http://wrong.domain.url/list.txt",
						"  clientGroupsBlock:",
						"    default:",
						"      - ads",
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
						Should(ContainElement(ContainSubstring("Error: can't start server: 1 error occurred")))
				})
			})
		})
	})
	Describe("Query blocking against external denylists", func() {
		When("external denylists are defined and available", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blockeddomain.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)

				Expect(err).Should(Succeed())
			})
			It("should download external list on startup and block queries", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("blockeddomain.com.", A)

				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("blockeddomain.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 6*60*60)),
						))

				Expect(getContainerLogs(ctx, blocky)).Should(BeEmpty())
			})
		})
	})
})
