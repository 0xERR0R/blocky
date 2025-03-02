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

var _ = Describe("Custom DNS tests", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("Custom DNS configuration", func() {
		BeforeEach(func(ctx context.Context) {
			// Create a mokka container for upstream DNS
			_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
			Expect(err).Should(Succeed())
		})

		When("Simple mapping is configured", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"customDNS:",
					"  customTTL: 30m",
					"  mapping:",
					"    printer.lan: 192.168.178.3",
					"    otherdevice.lan: 192.168.178.15,2001:0db8:85a3:08d3:1319:8a2e:0370:7344",
				)
				Expect(err).Should(Succeed())
			})

			It("Should resolve custom DNS entries", func(ctx context.Context) {
				By("Resolving a custom A record", func() {
					msg := util.NewMsgWithQuestion("printer.lan.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("printer.lan.", A, "192.168.178.3"),
								HaveTTL(BeNumerically("==", 1800)), // 30m = 1800s
							))
				})

				By("Resolving a custom entry with multiple IPs", func() {
					// Test A record
					msg := util.NewMsgWithQuestion("otherdevice.lan.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("otherdevice.lan.", A, "192.168.178.15"),
								HaveTTL(BeNumerically("==", 1800)),
							))

					// Test AAAA record
					msg = util.NewMsgWithQuestion("otherdevice.lan.", AAAA)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("otherdevice.lan.", AAAA, "2001:0db8:85a3:08d3:1319:8a2e:0370:7344"),
								HaveTTL(BeNumerically("==", 1800)),
							))
				})

				By("Resolving subdomains of custom entries", func() {
					msg := util.NewMsgWithQuestion("my.printer.lan.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("my.printer.lan.", A, "192.168.178.3"),
								HaveTTL(BeNumerically("==", 1800)),
							))
				})

				By("Falling back to upstream for non-custom domains", func() {
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

		When("Domain rewriting is configured", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"customDNS:",
					"  customTTL: 1h",
					"  rewrite:",
					"    home: lan",
					"    example.com: example-rewrite.com",
					"  mapping:",
					"    printer.lan: 192.168.178.3",
					"    example-rewrite.com: 1.2.3.4",
				)
				Expect(err).Should(Succeed())
			})

			It("Should rewrite domains according to configuration", func(ctx context.Context) {
				By("Rewriting 'home' to 'lan'", func() {
					msg := util.NewMsgWithQuestion("printer.home.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("printer.home.", A, "192.168.178.3"),
								HaveTTL(BeNumerically("==", 3600)), // 1h = 3600s
							))
				})

				By("Rewriting 'replace-me.com' to 'with-this.com'", func() {
					msg := util.NewMsgWithQuestion("a.example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("a.example.com.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 3600)),
							))
				})
			})
		})

		When("Zone file is configured", func() {
			BeforeEach(func(ctx context.Context) {
				Expect(err).Should(Succeed())

				// Create a container with the zone file
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"customDNS:",
					"  customTTL: 1h",
					"  zone: |",
					"    $ORIGIN example.com.",
					"    www 3600 A 1.2.3.5",
					"    @ 3600 CNAME www",
				)
				Expect(err).Should(Succeed())
			})

			It("Should resolve records from zone file", func(ctx context.Context) {
				By("Resolving A record from zone", func() {
					msg := util.NewMsgWithQuestion("www.example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("www.example.com.", A, "1.2.3.5"),
								HaveTTL(BeNumerically("==", 3600)),
							))
				})

				By("Resolving CNAME record from zone", func() {
					msg := util.NewMsgWithQuestion("example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("example.com.", CNAME, "www.example.com."),
								HaveTTL(BeNumerically("==", 3600)),
							))
				})
			})
		})

		When("filterUnmappedTypes is disabled", func() {
			BeforeEach(func(ctx context.Context) {
				// Create mokka container with AAAA response
				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet,
					`AAAA printer.lan/NOERROR("AAAA 2001:db8::1 123")`)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka2",
					"specialUseDomains:",
					"  enable: false",
					"customDNS:",
					"  customTTL: 1h",
					"  filterUnmappedTypes: false",
					"  mapping:",
					"    printer.lan: 192.168.178.3", // Only A record defined
				)
				Expect(err).Should(Succeed())
			})

			It("Should forward unmapped types to upstream", func(ctx context.Context) {
				By("Resolving defined A record locally", func() {
					msg := util.NewMsgWithQuestion("printer.lan.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("printer.lan.", A, "192.168.178.3"),
								HaveTTL(BeNumerically("==", 3600)),
							))
				})

				By("Forwarding unmapped AAAA query to upstream", func() {
					// This should be forwarded to upstream since we only defined A record
					// and filterUnmappedTypes is false
					msg := util.NewMsgWithQuestion("printer.lan.", AAAA)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("printer.lan.", AAAA, "2001:db8::1"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})
			})
		})

		When("filterUnmappedTypes is enabled (default)", func() {
			BeforeEach(func(ctx context.Context) {
				// Create mokka container with AAAA response
				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet,
					`AAAA printer.lan/NOERROR("AAAA 2001:db8::1 123")`)
				Expect(err).Should(Succeed())
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka2",
					"specialUseDomains:",
					"  enable: false",
					"customDNS:",
					"  customTTL: 1h",
					"  mapping:",
					"    printer.lan: 192.168.178.3", // Only A record defined
				)
				Expect(err).Should(Succeed())
			})

			It("Should filter unmapped types", func(ctx context.Context) {
				By("Resolving defined A record locally", func() {
					msg := util.NewMsgWithQuestion("printer.lan.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord("printer.lan.", A, "192.168.178.3"),
								HaveTTL(BeNumerically("==", 3600)),
							))
				})

				By("Returning empty result for unmapped AAAA query", func() {
					// This should return empty since we only defined A record
					// and filterUnmappedTypes is true (default)
					msg := util.NewMsgWithQuestion("printer.lan.", AAAA)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Answer).Should(BeEmpty())
				})
			})
		})

		When("Reverse DNS lookup is performed", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"customDNS:",
					"  customTTL: 1h",
					"  mapping:",
					"    printer.lan: 192.168.178.3",
					"    multi.lan: 192.168.178.4,192.168.178.5",
				)
				Expect(err).Should(Succeed())
			})

			It("Should resolve PTR records for defined IP addresses", func(ctx context.Context) {
				By("Resolving PTR record for a single IP mapping", func() {
					// Create a PTR query for 192.168.178.3
					ptrName, err := dns.ReverseAddr("192.168.178.3")
					Expect(err).Should(Succeed())

					msg := util.NewMsgWithQuestion(ptrName, PTR)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord(ptrName, PTR, "printer.lan."),
								HaveTTL(BeNumerically("==", 3600)), // 1h = 3600s
							))
				})

				By("Resolving PTR record for an IP with multiple domains", func() {
					// Create a PTR query for 192.168.178.4
					ptrName, err := dns.ReverseAddr("192.168.178.4")
					Expect(err).Should(Succeed())

					msg := util.NewMsgWithQuestion(ptrName, PTR)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(
							SatisfyAll(
								BeDNSRecord(ptrName, PTR, "multi.lan."),
								HaveTTL(BeNumerically("==", 3600)),
							))
				})

				By("Returning empty result for undefined IP address", func() {
					// Create a PTR query for 192.168.178.10 (not defined)
					ptrName, err := dns.ReverseAddr("192.168.178.10")
					Expect(err).Should(Succeed())

					msg := util.NewMsgWithQuestion(ptrName, PTR)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Answer).Should(BeEmpty())
				})
			})
		})
	})
})
