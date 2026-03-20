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

var _ = Describe("Query type filtering", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
			`A example.com/NOERROR("A 1.2.3.4 123")`,
			`AAAA example.com/NOERROR("AAAA 2001:db8::1 123")`,
			`MX example.com/NOERROR("MX 10 mail.example.com. 123")`,
		)
		Expect(err).Should(Succeed())
	})

	When("AAAA filtering is configured", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka",
				"filtering:",
				"  queryTypes:",
				"    - AAAA",
			)
			Expect(err).Should(Succeed())
		})

		It("should filter AAAA queries and return empty response", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("example.com.", AAAA)
			resp, err := doDNSRequest(ctx, blocky, msg)
			Expect(err).Should(Succeed())
			Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.Answer).Should(BeEmpty())
		})

		It("should pass through A queries normally", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("example.com.", A)
			Expect(doDNSRequest(ctx, blocky, msg)).
				Should(
					SatisfyAll(
						BeDNSRecord("example.com.", A, "1.2.3.4"),
						HaveTTL(BeNumerically("==", 123)),
					))
		})
	})

	When("multiple query types are filtered", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka",
				"filtering:",
				"  queryTypes:",
				"    - AAAA",
				"    - MX",
			)
			Expect(err).Should(Succeed())
		})

		It("should filter all configured query types", func(ctx context.Context) {
			By("filtering AAAA queries", func() {
				msg := util.NewMsgWithQuestion("example.com.", AAAA)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Answer).Should(BeEmpty())
			})

			By("filtering MX queries", func() {
				msg := util.NewMsgWithQuestion("example.com.", MX)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Answer).Should(BeEmpty())
			})

			By("passing through A queries", func() {
				msg := util.NewMsgWithQuestion("example.com.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("example.com.", A, "1.2.3.4"))
			})
		})
	})

	When("no filtering is configured", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka",
			)
			Expect(err).Should(Succeed())
		})

		It("should pass through all query types", func(ctx context.Context) {
			By("resolving A queries", func() {
				msg := util.NewMsgWithQuestion("example.com.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("example.com.", A, "1.2.3.4"))
			})

			By("resolving AAAA queries", func() {
				msg := util.NewMsgWithQuestion("example.com.", AAAA)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("example.com.", AAAA, "2001:db8::1"))
			})
		})
	})
})
