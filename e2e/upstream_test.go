package e2e

import (
	"context"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Upstream resolver configuration tests", func() {
	var blocky testcontainers.Container
	var err error

	Describe("'upstreams.init.strategy' parameter handling", func() {
		When("'upstreams.init.strategy' is fast and upstream server as IP is not reachable", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, tmpDir,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - 192.192.192.192",
					"  init:",
					"    strategy: fast",
				)
				Expect(err).Should(Succeed())
			})
			It("should start even if upstream server is not reachable", func(ctx context.Context) {
				Expect(blocky.IsRunning()).Should(BeTrue())
				Eventually(ctx, func() ([]string, error) {
					return getContainerLogs(ctx, blocky)
				}).Should(ContainElement(ContainSubstring("initial resolver test failed")))
			})
		})
		When("'upstreams.init.strategy' is fast and upstream server as host name is not reachable", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, tmpDir,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - some.wrong.host",
					"  init:",
					"    strategy: fast",
				)
				Expect(err).Should(Succeed())
			})
			It("should start even if upstream server is not reachable", func(ctx context.Context) {
				Expect(blocky.IsRunning()).Should(BeTrue())
				Expect(getContainerLogs(ctx, blocky)).Should(ContainElement(ContainSubstring("initial resolver test failed")))
			})
		})
		When("'upstreams.init.strategy' is failOnError and upstream as IP address server is not reachable", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, tmpDir,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - 192.192.192.192",
					"  init:",
					"    strategy: failOnError",
				)
				Expect(err).Should(HaveOccurred())
			})
			It("should not start", func(ctx context.Context) {
				Expect(blocky.IsRunning()).Should(BeFalse())
				Expect(getContainerLogs(ctx, blocky)).
					Should(ContainElement(ContainSubstring("no valid upstream for group default")))
			})
		})
		When("'upstreams.init.strategy' is failOnError and upstream server as host name is not reachable", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, tmpDir,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - some.wrong.host",
					"  init:",
					"    strategy: failOnError",
				)
				Expect(err).Should(HaveOccurred())
			})
			It("should not start", func(ctx context.Context) {
				Expect(blocky.IsRunning()).Should(BeFalse())
				Expect(getContainerLogs(ctx, blocky)).
					Should(ContainElement(ContainSubstring("no valid upstream for group default")))
			})
		})
	})
	Describe("'upstreams.timeout' parameter handling", func() {
		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka1",
				`A example.com/NOERROR("A 1.2.3.4 123")`,
				`A delay.com/delay(NOERROR("A 1.1.1.1 100"), "300ms")`)
			Expect(err).Should(Succeed())

			blocky, err = createBlockyContainer(ctx, tmpDir,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka1",
				"  timeout: 200ms",
			)
			Expect(err).Should(Succeed())
		})
		It("should consider the timeout parameter", func(ctx context.Context) {
			By("query without timeout", func() {
				msg := util.NewMsgWithQuestion("example.com.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 123)),
						))
			})

			By("query with timeout", func() {
				msg := util.NewMsgWithQuestion("delay.com.", A)

				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeServerFailure))
			})
		})
	})
})
