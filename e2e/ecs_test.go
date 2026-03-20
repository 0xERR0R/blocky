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
					`A blocked.com/NOERROR("A 5.6.7.8 300")`,
					`A allowed.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blocked.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"ecs:",
					"  useAsClient: true",
					"  ipv4Mask: 32",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    10.0.0.0/8:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("should apply blocking rules based on ECS subnet", func(ctx context.Context) {
				By("blocking domain when ECS IP matches client group", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					addECSOption(msg, net.ParseIP("10.0.0.1"), 32)

					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
				})

				By("allowing domain when ECS IP does not match client group", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					addECSOption(msg, net.ParseIP("192.168.1.1"), 32)

					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "5.6.7.8"))
				})
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

			It("should preserve ECS option in response", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)
				addECSOption(msg, net.ParseIP("10.1.2.3"), 32)

				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Answer).ShouldNot(BeEmpty())
				// Verify ECS option is preserved in the response
				Expect(resp).Should(HaveEdnsOption(dns.EDNS0SUBNET))
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

			It("should apply configured mask to ECS option", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)
				addECSOption(msg, net.ParseIP("10.1.2.3"), 32)

				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Answer).ShouldNot(BeEmpty())

				// Verify the ECS option in the response reflects the configured mask (24, not 32)
				opt := resp.IsEdns0()
				Expect(opt).ShouldNot(BeNil())

				var foundECS bool
				for _, o := range opt.Option {
					if subnet, ok := o.(*dns.EDNS0_SUBNET); ok {
						foundECS = true
						Expect(subnet.SourceNetmask).Should(BeNumerically("==", 24))
					}
				}
				Expect(foundECS).Should(BeTrue(), "Response should contain ECS option")
			})
		})
	})
})
