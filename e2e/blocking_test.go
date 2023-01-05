package e2e

import (
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("External lists and query blocking", func() {
	var blocky, httpServer, moka testcontainers.Container
	var err error
	BeforeEach(func() {
		moka, err = createDNSMokkaContainer("moka", `A google/NOERROR("A 1.2.3.4 123")`)

		Expect(err).Should(Succeed())
		DeferCleanup(moka.Terminate)
	})
	Describe("List download on startup", func() {
		When("external blacklist ist not available", func() {
			Context("startStrategy = blocking", func() {
				BeforeEach(func() {
					blocky, err = createBlockyContainer(tmpDir,
						"log:",
						"  level: warn",
						"upstream:",
						"  default:",
						"    - moka",
						"blocking:",
						"  startStrategy: blocking",
						"  blackLists:",
						"    ads:",
						"      - http://wrong.domain.url/list.txt",
						"  clientGroupsBlock:",
						"    default:",
						"      - ads",
					)

					Expect(err).Should(Succeed())
					DeferCleanup(blocky.Terminate)
				})

				It("should start with warning in log work without errors", func() {
					msg := util.NewMsgWithQuestion("google.com.", A)

					Expect(doDNSRequest(blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("google.com.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))

					Expect(getContainerLogs(blocky)).Should(ContainElement(ContainSubstring("error during file processing")))
				})
			})
			Context("startStrategy = failOnError", func() {
				BeforeEach(func() {
					blocky, err = createBlockyContainer(tmpDir,
						"log:",
						"  level: warn",
						"upstream:",
						"  default:",
						"    - moka",
						"blocking:",
						"  startStrategy: failOnError",
						"  blackLists:",
						"    ads:",
						"      - http://wrong.domain.url/list.txt",
						"  clientGroupsBlock:",
						"    default:",
						"      - ads",
					)

					Expect(err).Should(HaveOccurred())
					DeferCleanup(blocky.Terminate)
				})

				It("should fail to start", func() {
					Eventually(blocky.IsRunning, "30s").Should(BeFalse())

					Expect(getContainerLogs(blocky)).
						Should(ContainElement(ContainSubstring("Error: can't start server: 1 error occurred")))
				})
			})
		})
	})
	Describe("Query blocking against external blacklists", func() {
		When("external blacklists are defined and available", func() {
			BeforeEach(func() {
				httpServer, err = createHTTPServerContainer("httpserver", tmpDir, "list.txt", "blockeddomain.com")

				Expect(err).Should(Succeed())
				DeferCleanup(httpServer.Terminate)

				blocky, err = createBlockyContainer(tmpDir,
					"log:",
					"  level: warn",
					"upstream:",
					"  default:",
					"    - moka",
					"blocking:",
					"  blackLists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)

				Expect(err).Should(Succeed())
				DeferCleanup(blocky.Terminate)
			})
			It("should download external list on startup and block queries", func() {
				msg := util.NewMsgWithQuestion("blockeddomain.com.", A)

				Expect(doDNSRequest(blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("blockeddomain.com.", A, "0.0.0.0"),
							HaveTTL(BeNumerically("==", 6*60*60)),
						))

				Expect(getContainerLogs(blocky)).Should(BeEmpty())
			})
		})
	})
})
