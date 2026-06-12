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

var _ = Describe("DNS rebinding protection", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
			`A public.example.com/NOERROR("A 1.2.3.4 123")`,
			`A rebind.example.com/NOERROR("A 192.168.1.100 123")`,
			`AAAA rebind6.example.com/NOERROR("AAAA fd00::1 123")`,
			`A intranet.example.com/NOERROR("A 192.168.1.50 123")`,
		)
		Expect(err).Should(Succeed())
	})

	When("rebinding protection is enabled with an allowlist", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
				upstreams:
				  groups:
				    default:
				      - moka
				rebindingProtection:
				  enable: true
				  allowedDomains:
				    - intranet.example.com
				`))
			Expect(err).Should(Succeed())
		})

		It("should resolve public answers normally", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("public.example.com.", A)
			Expect(doDNSRequest(ctx, blocky, msg)).
				Should(
					SatisfyAll(
						BeDNSRecord("public.example.com.", A, "1.2.3.4"),
						HaveTTL(BeNumerically("==", 123)),
					))
		})

		It("should filter private IPv4 answers, also on repeat (cached) queries", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("rebind.example.com.", A)

			By("first query filtered", func() {
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Answer).Should(BeEmpty())
			})

			// the cache-path proof (one upstream call, re-filtered per hit) lives in the unit spec "chained above a caching resolver"
			By("repeat query still filtered", func() {
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Answer).Should(BeEmpty())
			})
		})

		It("should filter ULA IPv6 answers", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("rebind6.example.com.", AAAA)
			resp, err := doDNSRequest(ctx, blocky, msg)
			Expect(err).Should(Succeed())
			Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.Answer).Should(BeEmpty())
		})

		It("should pass through allowlisted domains with private IPs", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("intranet.example.com.", A)
			Expect(doDNSRequest(ctx, blocky, msg)).
				Should(BeDNSRecord("intranet.example.com.", A, "192.168.1.50"))
		})
	})

	When("rebinding protection is not configured", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
				upstreams:
				  groups:
				    default:
				      - moka
				`))
			Expect(err).Should(Succeed())
		})

		It("should pass through private answers (opt-in guard)", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("rebind.example.com.", A)
			Expect(doDNSRequest(ctx, blocky, msg)).
				Should(BeDNSRecord("rebind.example.com.", A, "192.168.1.100"))
		})
	})

	When("a conditional upstream serves an internal zone", func() {
		BeforeEach(func(ctx context.Context) {
			_, err = createDNSMokkaContainer(ctx, "moka-cond", e2eNet,
				`A router.home.lab/NOERROR("A 192.168.2.1 123")`)
			Expect(err).Should(Succeed())

			blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
				upstreams:
				  groups:
				    default:
				      - moka
				conditional:
				  mapping:
				    home.lab: moka-cond
				rebindingProtection:
				  enable: true
				`))
			Expect(err).Should(Succeed())
		})

		It("should resolve conditional answers with private IPs despite protection", func(ctx context.Context) {
			// end-to-end proof that conditional upstream answers bypass rebinding
			// protection (recognized by response type), no allowlist needed
			msg := util.NewMsgWithQuestion("router.home.lab.", A)

			By("first query", func() {
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("router.home.lab.", A, "192.168.2.1"))
			})

			// regression: conditional answers used to be cached and re-served as
			// CACHED, where the protection filtered them from the 2nd query onward
			By("repeat query", func() {
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("router.home.lab.", A, "192.168.2.1"))
			})
		})
	})
})
