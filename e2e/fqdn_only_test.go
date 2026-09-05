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

var _ = Describe("FQDN only mode", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
			`A example.com/NOERROR("A 1.2.3.4 123")`,
			`A myserver/NOERROR("A 5.6.7.8 300")`,
		)
		Expect(err).Should(Succeed())
	})

	When("fqdnOnly is enabled", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
				upstreams:
				  groups:
				    default:
				      - moka
				fqdnOnly:
				  enable: true
				`))
			Expect(err).Should(Succeed())
		})

		It("should reject non-FQDN queries with NXDOMAIN", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("myserver.", A)

			// the rejection must be a reply the client accepts: one that echoes the request id
			// and question. A bare Rcode-only message is discarded as an id mismatch, leaving
			// the client to time out instead of seeing the NXDOMAIN.
			resp, err := doDNSRequest(ctx, blocky, msg)
			Expect(err).Should(Succeed())
			Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			Expect(resp.Question).Should(Equal(msg.Question))
			Expect(resp.Answer).Should(BeEmpty())
		})

		It("should resolve FQDN queries normally", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("example.com.", A)
			Expect(doDNSRequest(ctx, blocky, msg)).
				Should(
					SatisfyAll(
						BeDNSRecord("example.com.", A, "1.2.3.4"),
						HaveTTL(BeNumerically("==", 123)),
					))
		})
	})

	When("fqdnOnly is disabled (default)", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
				upstreams:
				  groups:
				    default:
				      - moka
				`))
			Expect(err).Should(Succeed())
		})

		It("should resolve non-FQDN queries normally", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("myserver.", A)
			Expect(doDNSRequest(ctx, blocky, msg)).
				Should(
					SatisfyAll(
						BeDNSRecord("myserver.", A, "5.6.7.8"),
						HaveTTL(BeNumerically("==", 300)),
					))
		})
	})
})
