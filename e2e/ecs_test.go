package e2e

import (
	"context"
	"net"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

// addECSOption adds an EDNS0 CLIENT-SUBNET option to the given DNS message.
func addECSOption(msg *dns.Msg, ip net.IP, mask uint8) {
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT

	e := new(dns.EDNS0_SUBNET)
	if ip.To4() != nil {
		e.Family = 1 // IPv4
	} else {
		e.Family = 2 // IPv6
	}

	e.SourceNetmask = mask
	e.SourceScope = 0
	e.Address = ip

	o.Option = append(o.Option, e)
	msg.Extra = append(msg.Extra, o)
}

var _ = Describe("EDNS Client Subnet (ECS)", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("ECS as client identifier", func() {
		When("useAsClient is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A example.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"ecs:",
					"  useAsClient: true",
					"  ipv4Mask: 32",
				)
				Expect(err).Should(Succeed())
			})

			It("should resolve queries when ECS option is present", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)
				addECSOption(msg, net.ParseIP("10.0.0.1"), 32)

				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 300)),
						))
			})
		})
	})

	Describe("ECS forwarding", func() {
		When("forward is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A example.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"ecs:",
					"  forward: true",
					"  ipv4Mask: 24",
				)
				Expect(err).Should(Succeed())
			})

			It("should resolve queries with ECS forwarding enabled", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)
				addECSOption(msg, net.ParseIP("10.1.2.3"), 32)

				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 300)),
						))
			})
		})
	})

	Describe("ECS IPv4/IPv6 masks", func() {
		When("custom masks are configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A example.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"ecs:",
					"  useAsClient: true",
					"  ipv4Mask: 24",
					"  ipv6Mask: 48",
				)
				Expect(err).Should(Succeed())
			})

			It("should resolve queries with custom ECS masks configured", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)
				addECSOption(msg, net.ParseIP("10.1.2.3"), 32)

				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 300)),
						))
			})
		})
	})
})
