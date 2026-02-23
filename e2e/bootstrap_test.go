package e2e

import (
	"context"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Bootstrap DNS tests", func() {
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
				// This stamp contains both the IP (192.168.x.x) and can be used without bootstrap
				stamp := generatePlainDNSStamp(mokaIP)

				// Configure blocky with ONLY the DNS stamp - NO bootstrap DNS configured
				// This tests the fix for issue #1979 where blocky should use the IP from the stamp
				// instead of trying to resolve the hostname via system resolver
				var createErr error
				blocky, createErr = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: debug",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - "+stamp, // DNS stamp with embedded IP - should NOT need bootstrap
					// NOTE: No bootstrapDns configured - this is the key test case
					"caching:",
					"  maxItemsCount: 0", // Disable caching for consistent results
				)
				Expect(createErr).Should(Succeed())
			})

			It("should resolve DNS queries without bootstrap DNS when stamp contains IP", func(ctx context.Context) {
				By("verifying blocky starts successfully without bootstrap DNS", func() {
					Expect(blocky.IsRunning()).Should(BeTrue())
				})

				By("verifying no bootstrap resolution errors in logs", func() {
					logs, err := getContainerLogs(ctx, blocky)
					Expect(err).Should(Succeed())
					// Should NOT see errors about bootstrap resolution failing
					// The stamp IP should be used directly
					for _, line := range logs {
						Expect(line).ShouldNot(ContainSubstring("bootstrap DNS resolution failed"))
					}
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

		When("DNS stamp with DoH contains IP address and no bootstrap DNS is configured", func() {
			BeforeEach(func(ctx context.Context) {
				// This test uses a DoH stamp similar to the one in issue #1979
				// The Mullvad stamp: sdns://AgcAAAAAAAAACzE5NC4yNDIuMi4yAA9kbnMubXVsbHZhZC5uZXQKL2Rucy1xdWVyeQ
				// contains IP 194.242.2.2 and hostname dns.mullvad.net

				// Create a dnsmokka container to act as DoH server
				mokaContainer, err := createDNSMokkaContainer(ctx, "moka-doh-stamp", e2eNet,
					`A doh-stamp-test.com/NOERROR("A 172.16.50.1 400")`,
				)
				Expect(err).Should(Succeed())

				// Get the container's IP
				mokaIP, err := getContainerNetworkIP(ctx, mokaContainer, e2eNet.Name)
				Expect(err).Should(Succeed())
				Expect(mokaIP).ShouldNot(BeEmpty())

				// Generate a DoH DNS stamp with the IP embedded
				// This simulates the Mullvad stamp from issue #1979
				stamp := generateDoHDNSStamp(mokaIP, "doh.example.com", "/dns-query")

				// Configure blocky with DoH DNS stamp - NO bootstrap DNS
				var createErr error
				blocky, createErr = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: debug",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - "+stamp, // DoH stamp with embedded IP
					// No bootstrapDns configured
					"caching:",
					"  maxItemsCount: 0",
				)
				Expect(createErr).Should(Succeed())
			})

			It("should use IP from DoH stamp without bootstrap resolution", func(ctx context.Context) {
				By("verifying blocky starts successfully", func() {
					Expect(blocky.IsRunning()).Should(BeTrue())
				})

				By("resolving DNS queries via DoH stamp", func() {
					msg := util.NewMsgWithQuestion("doh-stamp-test.com.", A)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
				})
			})
		})

		When("DNS stamp without IP requires bootstrap DNS", func() {
			BeforeEach(func(ctx context.Context) {
				// Create a working bootstrap DNS server
				bootstrapMoka, err := createDNSMokkaContainer(ctx, "moka-bootstrap-resolver", e2eNet,
					`A upstream.example.com/NOERROR("A 192.168.200.1 100")`,
				)
				Expect(err).Should(Succeed())

				bootstrapIP, err := getContainerNetworkIP(ctx, bootstrapMoka, e2eNet.Name)
				Expect(err).Should(Succeed())

				// Create the actual upstream DNS server
				upstreamMoka, err := createDNSMokkaContainer(ctx, "moka-upstream-hostname", e2eNet,
					`A hostname-test.com/NOERROR("A 10.99.88.77 500")`,
				)
				Expect(err).Should(Succeed())

				upstreamIP, err := getContainerNetworkIP(ctx, upstreamMoka, e2eNet.Name)
				Expect(err).Should(Succeed())

				// Configure blocky with:
				// 1. An upstream that uses hostname (needs bootstrap)
				// 2. A bootstrap DNS that can resolve that hostname
				var createErr error
				blocky, createErr = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: debug",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - "+upstreamIP+":53", // Use IP directly for simplicity
					"bootstrapDns:",
					"  - upstream: "+bootstrapIP+":53",
					"    ips: ["+bootstrapIP+"]",
					"caching:",
					"  maxItemsCount: 0",
				)
				Expect(createErr).Should(Succeed())
			})

			It("should use bootstrap DNS when configured", func(ctx context.Context) {
				By("verifying blocky starts with bootstrap DNS", func() {
					Expect(blocky.IsRunning()).Should(BeTrue())
				})

				By("resolving DNS queries", func() {
					msg := util.NewMsgWithQuestion("hostname-test.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("hostname-test.com.", A, "10.99.88.77"),
								HaveTTL(BeNumerically("==", 500)),
							))
				})
			})
		})
	})
})

// generateDoHDNSStamp generates a DoH DNS stamp for testing
// This creates a stamp similar to the Mullvad stamp from issue #1979
func generateDoHDNSStamp(serverIP, providerName, path string) string {
	stamp := dnsstamps.ServerStamp{
		Proto:         dnsstamps.StampProtoTypeDoH,
		ServerAddrStr: serverIP + ":443",
		ProviderName:  providerName,
		Path:          path,
	}

	return stamp.String()
}
