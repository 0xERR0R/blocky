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

var _ = Describe("DNS64 e2e tests", Label("e2e"), func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("Basic DNS64 synthesis", func() {
		When("AAAA query returns no records but A record exists", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS server
				// Returns no AAAA record but returns A record for ipv4only.example.com
				_, err = createDNSMokkaContainer(ctx, "upstream", e2eNet,
					// AAAA query returns empty response (NOERROR with no records)
					`AAAA ipv4only.example.com/NOERROR()`,
					// A query returns IPv4 address
					`A ipv4only.example.com/NOERROR("A 192.0.2.1 300")`,
				)
				Expect(err).Should(Succeed())

				// Create blocky with DNS64 enabled
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: info",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - upstream",
					"# Enable DNS64 with default well-known prefix",
					"dns64:",
					"  enable: true",
					"  prefixes:",
					"    - 64:ff9b::/96",
				)
				Expect(err).Should(Succeed())
			})

			It("should synthesize AAAA record from A record", func(ctx context.Context) {
				By("querying for AAAA record", func() {
					msg := util.NewMsgWithQuestion("ipv4only.example.com.", AAAA)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Should get synthesized AAAA record
					Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Answer).Should(HaveLen(1))

					// Verify the synthesized AAAA record
					// 192.0.2.1 should be embedded in 64:ff9b::/96 prefix
					// Result: 64:ff9b::192.0.2.1 (or 64:ff9b::c000:201 in hex)
					Expect(resp).Should(
						SatisfyAll(
							BeDNSRecord("ipv4only.example.com.", AAAA, "64:ff9b::c000:201"),
							HaveTTL(BeNumerically("<=", 300)),
						))
				})

				By("verifying TTL matches A record TTL", func() {
					msg := util.NewMsgWithQuestion("ipv4only.example.com.", AAAA)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// TTL should be from A record (300 seconds)
					Expect(resp.Answer[0].Header().Ttl).Should(BeNumerically("<=", 300))
				})
			})
		})

		When("AAAA query returns native IPv6 address", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS server
				// Returns native AAAA record
				_, err = createDNSMokkaContainer(ctx, "upstream", e2eNet,
					// AAAA query returns native IPv6 address
					`AAAA ipv6native.example.com/NOERROR("AAAA 2001:db8::1 300")`,
					// A record also exists but should not be queried
					`A ipv6native.example.com/NOERROR("A 192.0.2.1 300")`,
				)
				Expect(err).Should(Succeed())

				// Create blocky with DNS64 enabled
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: info",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - upstream",
					"dns64:",
					"  enable: true",
					"  prefixes:",
					"    - 64:ff9b::/96",
				)
				Expect(err).Should(Succeed())
			})

			It("should return native AAAA record without synthesis", func(ctx context.Context) {
				By("querying for AAAA record", func() {
					msg := util.NewMsgWithQuestion("ipv6native.example.com.", AAAA)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Should get native AAAA record, not synthesized
					Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Answer).Should(HaveLen(1))

					// Verify it's the native IPv6 address, not a synthesized one
					Expect(resp).Should(
						SatisfyAll(
							BeDNSRecord("ipv6native.example.com.", AAAA, "2001:db8::1"),
							HaveTTL(BeNumerically("<=", 300)),
						))
				})

				By("verifying no A query was made (no synthesis)", func() {
					// If we query again, it should still return the native AAAA
					msg := util.NewMsgWithQuestion("ipv6native.example.com.", AAAA)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Should still be native IPv6, proving no synthesis occurred
					Expect(resp).Should(BeDNSRecord("ipv6native.example.com.", AAAA, "2001:db8::1"))
				})
			})
		})
	})

	Describe("Advanced DNS64 scenarios", func() {
		When("a domain has a CNAME to an IPv4-only domain", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS server
				_, err = createDNSMokkaContainer(ctx, "upstream", e2eNet,
					// AAAA query for cname.example.com returns empty response
					`AAAA cname.example.com/NOERROR()`,
					// A query for cname.example.com returns CNAME chain with A record
					`A cname.example.com/NOERROR("CNAME ipv4only.example.com. 300", "A 192.0.2.2 300")`,
				)
				Expect(err).Should(Succeed())

				// Create blocky with DNS64 enabled
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: info",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - upstream",
					"dns64:",
					"  enable: true",
					"  prefixes:",
					"    - 64:ff9b::/96",
				)
				Expect(err).Should(Succeed())
			})

			It("should synthesize AAAA record and preserve CNAME chain", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("cname.example.com.", AAAA)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())

				// Should get CNAME record and synthesized AAAA record
				Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Answer).Should(HaveLen(2))

				// Verify the CNAME and synthesized AAAA record
				// Note: DNSMokka returns A record with the queried name, so synthesized AAAA also has that name
				Expect(resp).Should(
					SatisfyAll(
						BeDNSRecord("cname.example.com.", CNAME, "ipv4only.example.com."),
						BeDNSRecord("cname.example.com.", AAAA, "64:ff9b::c000:202"),
					))
			})
		})

		When("a CNAME in the chain has a shorter TTL than the A record", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS server
				_, err = createDNSMokkaContainer(ctx, "upstream", e2eNet,
					// AAAA query returns empty response
					`AAAA short-ttl-cname.example.com/NOERROR()`,
					// A query returns CNAME with TTL 60 and A record with TTL 300
					// The synthesized AAAA should use minimum TTL (60)
					`A short-ttl-cname.example.com/NOERROR("CNAME target.example.com. 60", "A 192.0.2.3 300")`,
				)
				Expect(err).Should(Succeed())

				// Create blocky with DNS64 enabled
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: info",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - upstream",
					"dns64:",
					"  enable: true",
					"  prefixes:",
					"    - 64:ff9b::/96",
				)
				Expect(err).Should(Succeed())
			})

			It("should use the minimum TTL from the CNAME chain for the synthesized record", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("short-ttl-cname.example.com.", AAAA)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())

				// Should get CNAME record and synthesized AAAA record
				Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Answer).Should(HaveLen(2))

				// Verify the CNAME is present
				Expect(resp).Should(BeDNSRecord("short-ttl-cname.example.com.", CNAME, "target.example.com."))

				// Verify the synthesized AAAA record with correct IP
				// Note: DNSMokka returns A record with the queried name, so synthesized AAAA also has that name
				Expect(resp).Should(BeDNSRecord("short-ttl-cname.example.com.", AAAA, "64:ff9b::c000:203"))

				// The synthesized AAAA TTL should be the minimum from the chain (60, not 300)
				var aaaaTTL uint32
				for _, rr := range resp.Answer {
					if rr.Header().Rrtype == dns.TypeAAAA {
						aaaaTTL = rr.Header().Ttl

						break
					}
				}
				Expect(aaaaTTL).Should(BeNumerically("<=", 60))
			})
		})

		When("upstream returns a non-synthesized AAAA record in the exclusion range", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS server
				_, err = createDNSMokkaContainer(ctx, "upstream", e2eNet,
					// AAAA query returns a record that should be excluded (from ::ffff:0:0/96 range)
					`AAAA excluded.example.com/NOERROR("AAAA ::ffff:192.0.2.4 300")`,
					// A record also exists and should be used for synthesis
					`A excluded.example.com/NOERROR("A 198.51.100.5 300")`,
				)
				Expect(err).Should(Succeed())

				// Create blocky with DNS64 enabled
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: info",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - upstream",
					"dns64:",
					"  enable: true",
					"  prefixes:",
					"    - 64:ff9b::/96",
				)
				Expect(err).Should(Succeed())
			})

			It("should ignore the excluded record and synthesize from the A record", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("excluded.example.com.", AAAA)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())

				// Should get a single synthesized AAAA record, not the excluded one
				Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Answer).Should(HaveLen(1))

				// Verify the synthesized record is from the A record (198.51.100.5)
				// and not the excluded AAAA record (::ffff:192.0.2.4)
				Expect(resp).Should(BeDNSRecord("excluded.example.com.", AAAA, "64:ff9b::c633:6405"))
			})
		})

		When("multiple DNS64 prefixes are configured", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS server
				_, err = createDNSMokkaContainer(ctx, "upstream", e2eNet,
					// AAAA query returns no records
					`AAAA ipv4only.example.com/NOERROR()`,
					// A query returns an IPv4 address
					`A ipv4only.example.com/NOERROR("A 192.0.2.5 300")`,
				)
				Expect(err).Should(Succeed())

				// Create blocky with two DNS64 prefixes
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: info",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - upstream",
					"dns64:",
					"  enable: true",
					"  prefixes:",
					"    - 64:ff9b::/96",
					"    - 2001:db8:1::/48",
				)
				Expect(err).Should(Succeed())
			})

			It("should synthesize an AAAA record for each prefix", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("ipv4only.example.com.", AAAA)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())

				// Should get two synthesized AAAA records
				Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Answer).Should(HaveLen(2))

				// Verify both synthesized records are present
				// The order can vary, so check for both
				Expect(resp).Should(
					SatisfyAll(
						BeDNSRecord("ipv4only.example.com.", AAAA, "64:ff9b::c000:205"),
						BeDNSRecord("ipv4only.example.com.", AAAA, "2001:db8:1:c000:2:500::"),
					))
			})
		})

		When("caching is enabled with DNS64", func() {
			BeforeEach(func(ctx context.Context) {
				// Setup mock DNS server
				_, err = createDNSMokkaContainer(ctx, "upstream", e2eNet,
					`AAAA cached.example.com/NOERROR()`,
					`A cached.example.com/NOERROR("A 192.0.2.6 300")`,
				)
				Expect(err).Should(Succeed())

				// Create blocky with DNS64 and caching enabled
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: debug",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - upstream",
					"dns64:",
					"  enable: true",
					"  prefixes:",
					"    - 64:ff9b::/96",
					"caching:",
					"  maxTime: 1h",
				)
				Expect(err).Should(Succeed())
			})

			It("should work correctly with caching enabled", func(ctx context.Context) {
				By("first query should synthesize AAAA record", func() {
					msg := util.NewMsgWithQuestion("cached.example.com.", AAAA)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Verify the synthesized record
					Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Answer).Should(HaveLen(1))
					Expect(resp).Should(BeDNSRecord("cached.example.com.", AAAA, "64:ff9b::c000:206"))
				})

				By("second query should return same synthesized result", func() {
					msg := util.NewMsgWithQuestion("cached.example.com.", AAAA)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Verify the synthesized record is still correct
					Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Answer).Should(HaveLen(1))
					Expect(resp).Should(BeDNSRecord("cached.example.com.", AAAA, "64:ff9b::c000:206"))
				})
			})
		})
	})
})
