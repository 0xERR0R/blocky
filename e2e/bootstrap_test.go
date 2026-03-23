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

var _ = Describe("Bootstrap DNS tests", Label("e2e"), func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("DNS Stamp bootstrapping", func() {
		When("DNS stamp contains IP address and no bootstrap DNS is configured", func() {
			BeforeEach(func(ctx context.Context) {
				// Create a dnsmokka container that will be our upstream DNS server
				mokaContainer, err := createDNSMokkaContainer(ctx, "moka-stamp-bootstrap", e2eNet,
					`A bootstrap-test.com/NOERROR("A 192.168.100.1 300")`,
					`A no-bootstrap-required.com/NOERROR("A 10.20.30.40 600")`,
				)
				Expect(err).Should(Succeed())

				// Get the container's IP within the docker network
				mokaIP, err := getContainerNetworkIP(ctx, mokaContainer, e2eNet.Name)
				Expect(err).Should(Succeed())
				Expect(mokaIP).ShouldNot(BeEmpty())

				// Generate DNS stamp with the IP address embedded
				// This stamp contains both the IP and can be used without bootstrap
				stamp := generatePlainDNSStamp(mokaIP)

				// Configure blocky with ONLY the DNS stamp - NO bootstrap DNS configured
				// This tests the fix for issue #1979 where blocky should use the IP from the stamp
				// instead of trying to resolve the hostname via system resolver
				var createErr error
				blocky, createErr = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: debug
					upstreams:
					  groups:
					    default:
					      - `+stamp+`
					caching:
					  maxItemsCount: 0
				`))
				Expect(createErr).Should(Succeed())
			})

			It("should resolve DNS queries without bootstrap DNS when stamp contains IP", func(ctx context.Context) {
				By("verifying blocky starts successfully without bootstrap DNS", func() {
					Expect(blocky.IsRunning()).Should(BeTrue())
				})

				By("resolving DNS queries successfully", func() {
					msg := util.NewMsgWithQuestion("bootstrap-test.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("bootstrap-test.com.", A, "192.168.100.1"),
								HaveTTL(BeNumerically("==", 300)),
							))
				})

				By("resolving another query to verify consistent behavior", func() {
					msg := util.NewMsgWithQuestion("no-bootstrap-required.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("no-bootstrap-required.com.", A, "10.20.30.40"),
								HaveTTL(BeNumerically("==", 600)),
							))
				})
			})
		})

		When("DNS stamp with IPv6 contains IP address and no bootstrap DNS is configured", func() {
			BeforeEach(func(ctx context.Context) {
				// Use IPv6-enabled network for this test
				e2eNet = getRandomIPv6Network(ctx)

				// Create a dnsmokka container
				mokaContainer, err := createDNSMokkaContainer(ctx, "moka-stamp-ipv6", e2eNet,
					`A ipv6-stamp-test.com/NOERROR("A 172.16.60.1 400")`,
				)
				Expect(err).Should(Succeed())

				// Get the container's IPv6 address
				inspect, err := mokaContainer.Inspect(ctx)
				Expect(err).Should(Succeed())

				var ipv6IP string
				for _, netSettings := range inspect.NetworkSettings.Networks {
					if netSettings.GlobalIPv6Address != "" {
						ipv6IP = netSettings.GlobalIPv6Address

						break
					}
				}
				Expect(ipv6IP).ShouldNot(BeEmpty(), "Container should have an IPv6 address on the IPv6-enabled network")

				// Generate DNS stamp with IPv6 address embedded
				stamp := generatePlainDNSStamp("[" + ipv6IP + "]")

				var createErr error
				blocky, createErr = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: debug
					upstreams:
					  groups:
					    default:
					      - `+stamp+`
					caching:
					  maxItemsCount: 0
				`))
				Expect(createErr).Should(Succeed())
			})

			It("should resolve DNS queries using IPv6 from stamp", func(ctx context.Context) {
				By("verifying blocky starts successfully", func() {
					Expect(blocky.IsRunning()).Should(BeTrue())
				})

				By("resolving DNS queries", func() {
					msg := util.NewMsgWithQuestion("ipv6-stamp-test.com.", A)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
				})
			})
		})

		When("multiple DNS stamps are configured", func() {
			BeforeEach(func(ctx context.Context) {
				// Create two dnsmokka containers
				moka1, err := createDNSMokkaContainer(ctx, "moka-stamp-1", e2eNet,
					`A multi-stamp-test.com/NOERROR("A 10.10.10.1 200")`,
				)
				Expect(err).Should(Succeed())

				moka2, err := createDNSMokkaContainer(ctx, "moka-stamp-2", e2eNet,
					`A multi-stamp-test.com/NOERROR("A 10.10.10.2 200")`,
				)
				Expect(err).Should(Succeed())

				ip1, err := getContainerNetworkIP(ctx, moka1, e2eNet.Name)
				Expect(err).Should(Succeed())

				ip2, err := getContainerNetworkIP(ctx, moka2, e2eNet.Name)
				Expect(err).Should(Succeed())

				stamp1 := generatePlainDNSStamp(ip1)
				stamp2 := generatePlainDNSStamp(ip2)

				var createErr error
				blocky, createErr = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: debug
					upstreams:
					  groups:
					    default:
					      - `+stamp1+`
					      - `+stamp2+`
					  strategy: parallel_best
					caching:
					  maxItemsCount: 0
				`))
				Expect(createErr).Should(Succeed())
			})

			It("should use multiple stamp-based upstreams", func(ctx context.Context) {
				By("verifying blocky starts successfully", func() {
					Expect(blocky.IsRunning()).Should(BeTrue())
				})

				By("resolving DNS queries with multiple stamp upstreams", func() {
					msg := util.NewMsgWithQuestion("multi-stamp-test.com.", A)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Answer).Should(HaveLen(1))

					aRecord, ok := resp.Answer[0].(*dns.A)
					Expect(ok).Should(BeTrue())
					// Should get response from one of the upstreams
					ip := aRecord.A.String()
					Expect(ip).Should(Or(Equal("10.10.10.1"), Equal("10.10.10.2")))
				})
			})
		})

		When("DNS stamp is configured with bootstrap DNS", func() {
			BeforeEach(func(ctx context.Context) {
				// Create upstream DNS server
				mokaContainer, err := createDNSMokkaContainer(ctx, "moka-with-bootstrap", e2eNet,
					`A with-bootstrap-test.com/NOERROR("A 192.168.50.1 300")`,
				)
				Expect(err).Should(Succeed())

				mokaIP, err := getContainerNetworkIP(ctx, mokaContainer, e2eNet.Name)
				Expect(err).Should(Succeed())

				stamp := generatePlainDNSStamp(mokaIP)

				// Create a separate bootstrap DNS server
				bootstrapMoka, err := createDNSMokkaContainer(ctx, "moka-bootstrap", e2eNet,
					`A bootstrap.example.com/NOERROR("A 192.168.99.1 100")`,
				)
				Expect(err).Should(Succeed())

				bootstrapIP, err := getContainerNetworkIP(ctx, bootstrapMoka, e2eNet.Name)
				Expect(err).Should(Succeed())

				// Configure with both stamp-based upstream and bootstrap DNS
				var createErr error
				blocky, createErr = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: debug
					upstreams:
					  groups:
					    default:
					      - `+stamp+`
					bootstrapDns:
					  - upstream: `+bootstrapIP+`:53
					    ips: [`+bootstrapIP+`]
					caching:
					  maxItemsCount: 0
				`))
				Expect(createErr).Should(Succeed())
			})

			It("should work with both stamp upstream and bootstrap DNS configured", func(ctx context.Context) {
				By("verifying blocky starts successfully", func() {
					Expect(blocky.IsRunning()).Should(BeTrue())
				})

				By("resolving DNS queries via stamp upstream", func() {
					msg := util.NewMsgWithQuestion("with-bootstrap-test.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("with-bootstrap-test.com.", A, "192.168.50.1"),
								HaveTTL(BeNumerically("==", 300)),
							))
				})
			})
		})
	})
})
