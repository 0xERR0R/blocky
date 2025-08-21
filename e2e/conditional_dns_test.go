package e2e

import (
	"context"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Conditional DNS resolution tests", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("Conditional DNS forwarding", func() {
		When("Conditional upstream is configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A lan/NOERROR("A 1.2.3.4 123")`)
				Expect(err).Should(Succeed())

				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet, `A google/NOERROR("A 5.6.7.8 123")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka2",
					"conditional:",
					"  mapping:",
					"    lan: moka1",
				)
				Expect(err).Should(Succeed())
			})

			It("Should use conditional upstream for specific domain", func(ctx context.Context) {
				By("forwarding 'my.device.lan' to moka1", func() {
					msg := util.NewMsgWithQuestion("my.device.lan.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("my.device.lan.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})

				By("forwarding 'google.com' to default upstream moka2", func() {
					msg := util.NewMsgWithQuestion("google.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("google.com.", A, "5.6.7.8"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})
			})
		})

		When("Conditional upstream is configured for root", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
				Expect(err).Should(Succeed())

				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet, `A my/NOERROR("A 5.6.7.8 123")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"conditional:",
					"  mapping:",
					"    .: moka2",
				)
				Expect(err).Should(Succeed())
			})

			It("Should use conditional upstream for any unqualifieddomain", func(ctx context.Context) {
				By("forwarding 'my' to moka2", func() {
					msg := util.NewMsgWithQuestion("my.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("my.", A, "5.6.7.8"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})

				By("forwarding 'google.com' to default upstream", func() {
					msg := util.NewMsgWithQuestion("google.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("google.com.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})
			})
		})

		When("Rewrite is configured for conditional upstream", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A lan/NOERROR("A 1.2.3.4 123")`)
				Expect(err).Should(Succeed())

				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet, `A google/NOERROR("A 5.6.7.8 123")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka2",
					"conditional:",
					"  rewrite:",
					"    home: lan",
					"  mapping:",
					"    lan: moka1",
				)
				Expect(err).Should(Succeed())
			})

			It("Should use conditional upstream for rewritten domain", func(ctx context.Context) {
				By("forwarding 'my.device.home' to moka1 after rewrite to 'lan'", func() {
					msg := util.NewMsgWithQuestion("my.device.home.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("my.device.home.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})

				By("forwarding 'google.com' to default upstream moka2", func() {
					msg := util.NewMsgWithQuestion("google.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("google.com.", A, "5.6.7.8"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})
			})
		})
	})
})
