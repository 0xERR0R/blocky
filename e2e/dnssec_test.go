package e2e

import (
	"context"
	"fmt"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("DNSSEC validation", Label("dnssec"), func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("DNSSEC validation support", func() {
		Context("with DNSSEC validation enabled", func() {
			When("upstream returns response with invalid DNSSEC signatures", func() {
				BeforeEach(func(ctx context.Context) {
					// Create a mock DNS server that returns DNSSEC records but with invalid signatures
					// This simulates a compromised or broken upstream
					rrsigRecord := `RRSIG A 13 3 300 20991231235959 20230101000000 12345 ` +
						`invalid.dnssec.example. YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3Q= 300`
					_, err = createDNSMokkaContainer(ctx, "moka-dnssec", e2eNet,
						// Return A record with RRSIG but signature is fake/invalid (valid base64 though)
						// Note: Using .example TLD instead of .test (SUDN resolver blocks .test)
						`A invalid.dnssec.example/NOERROR("A 192.0.2.1 300", "`+rrsigRecord+`")`,
					)
					Expect(err).Should(Succeed())

					// Create blocky with DNSSEC validation enabled
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka-dnssec",
						"dnssec:",
						"  validate: true",
					)
					Expect(err).Should(Succeed())
				})

				It("should reject the response and return SERVFAIL", func(ctx context.Context) {
					// DNSSEC validation is now implemented!

					msg := util.NewMsgWithQuestion("invalid.dnssec.example.", A)
					msg.SetEdns0(4096, true) // Enable DNSSEC OK (DO) bit

					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Should return SERVFAIL because DNSSEC validation failed
					Expect(resp.Rcode).Should(Equal(dns.RcodeServerFailure),
						"Expected SERVFAIL for invalid DNSSEC signatures")

					// Should NOT have the Authenticated Data (AD) flag set
					Expect(resp.AuthenticatedData).Should(BeFalse(),
						"AD flag should not be set for failed DNSSEC validation")
				})
			})

			When("upstream returns RRSIG with matching valid DNSKEY", func() {
				var validData *DNSSECTestData

				BeforeEach(func(ctx context.Context) {
					// Generate cryptographically valid DNSSEC data for a TLD
					// Using "example." as the zone (TLD) so the trust anchor is at the top level
					var genErr error
					validData, genErr = GenerateValidDNSSEC("example.", "www.example.", "192.0.2.10")
					Expect(genErr).Should(Succeed())

					// Format records for mokka
					aRecordStr := FormatRecordForMokka(validData.ARecord)
					rrsigStr := FormatRecordForMokka(validData.RRSIG)
					dnskeyStr := FormatRecordForMokka(validData.DNSKEY)

					// Create mokka with properly signed DNSSEC records
					// Mokka needs to handle two query types:
					// 1. A query for www.example -> return A + RRSIG
					// 2. DNSKEY query for example -> return DNSKEY
					_, err = createDNSMokkaContainer(ctx, "moka-dnssec-valid", e2eNet,
						fmt.Sprintf(`A www.example/NOERROR("%s", "%s")`, aRecordStr, rrsigStr),
						fmt.Sprintf(`DNSKEY example/NOERROR("%s")`, dnskeyStr),
					)
					Expect(err).Should(Succeed())

					// Create blocky with DNSSEC validation enabled
					// Add the generated DNSKEY as a trust anchor for the example. TLD
					// This makes example. a trusted zone, similar to how root trust anchors work
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka-dnssec-valid",
						"dnssec:",
						"  validate: true",
						"  trustAnchors:",
						fmt.Sprintf("    - \"%s\"", validData.DNSKEY.String()),
						"log:",
						"  level: debug",
					)
					Expect(err).Should(Succeed())
				})

				It("should validate RRSIG against DNSKEY and return success", func(ctx context.Context) {
					msg := util.NewMsgWithQuestion("www.example.", A)
					msg.SetEdns0(4096, true) // Enable DNSSEC OK (DO) bit

					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Should return NOERROR because DNSSEC validation succeeded
					Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess),
						"Expected NOERROR for valid DNSSEC signatures")

					// Should have the Authenticated Data (AD) flag set
					Expect(resp.AuthenticatedData).Should(BeTrue(),
						"AD flag should be set after successful DNSSEC validation")

					// Should have the A record in the answer
					Expect(resp.Answer).Should(ContainElement(
						BeDNSRecord("www.example.", A, "192.0.2.10"),
					))
				})
			})

			When("upstream returns RRSIG with wrong DNSKEY signature", func() {
				BeforeEach(func(ctx context.Context) {
					// Generate DNSSEC data where RRSIG and DNSKEY don't match
					// Using "mismatch." as TLD for same reason as happy path test
					var genErr error
					validData, wrongKey, genErr := GenerateMismatchedDNSSEC("mismatch.", "www.mismatch.", "192.0.2.20")
					Expect(genErr).Should(Succeed())

					// Format records for mokka
					aRecordStr := FormatRecordForMokka(validData.ARecord)
					rrsigStr := FormatRecordForMokka(validData.RRSIG) // Signed with keyA
					wrongKeyStr := FormatRecordForMokka(wrongKey)     // Different keyB

					// Create mokka that returns RRSIG signed with one key, but DNSKEY is different
					// This should cause validation to fail
					_, err = createDNSMokkaContainer(ctx, "moka-dnssec-mismatch", e2eNet,
						fmt.Sprintf(`A www.mismatch/NOERROR("%s", "%s")`, aRecordStr, rrsigStr),
						fmt.Sprintf(`DNSKEY mismatch/NOERROR("%s")`, wrongKeyStr),
					)
					Expect(err).Should(Succeed())

					// Create blocky with DNSSEC validation enabled
					// Add the wrong key as trust anchor so chain validation passes,
					// but signature verification will fail
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka-dnssec-mismatch",
						"dnssec:",
						"  validate: true",
						"  trustAnchors:",
						fmt.Sprintf("    - \"%s\"", wrongKey.String()),
						"log:",
						"  level: debug",
					)
					Expect(err).Should(Succeed())
				})

				It("should detect signature mismatch and return SERVFAIL", func(ctx context.Context) {
					msg := util.NewMsgWithQuestion("www.mismatch.", A)
					msg.SetEdns0(4096, true) // Enable DNSSEC OK (DO) bit

					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Should return SERVFAIL because RRSIG signature doesn't match DNSKEY
					Expect(resp.Rcode).Should(Equal(dns.RcodeServerFailure),
						"Expected SERVFAIL when RRSIG doesn't match DNSKEY")

					// Should NOT have the Authenticated Data (AD) flag set
					Expect(resp.AuthenticatedData).Should(BeFalse(),
						"AD flag should not be set for failed DNSSEC validation")
				})
			})

			When("upstream returns valid DNSSEC-signed response", func() {
				BeforeEach(func(ctx context.Context) {
					// For now, use a real DNSSEC-validating upstream (Cloudflare)
					// In the future, we could mock a proper DNSSEC-signed response
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - 1.1.1.1", // Cloudflare validates DNSSEC
						"dnssec:",
						"  validate: true",
					)
					Expect(err).Should(Succeed())
				})

				It("should accept valid DNSSEC and set AD flag", func(ctx context.Context) {
					// DNSSEC validation is now implemented!

					msg := util.NewMsgWithQuestion("cloudflare.com.", A)
					msg.SetEdns0(4096, true) // Enable DNSSEC OK (DO) bit

					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Should return NOERROR
					Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))

					// Should have the Authenticated Data (AD) flag set
					// NOTE: Currently Blocky just passes through the AD flag from upstream
					// After implementing validation, Blocky should set this flag itself
					Expect(resp.AuthenticatedData).Should(BeTrue(),
						"AD flag should be set after successful DNSSEC validation")

					// Should have answer records
					Expect(resp.Answer).ShouldNot(BeEmpty())
				})
			})

			When("upstream returns complete DNSSEC chain with DS records", func() {
				var chainData *DNSSECChainData

				BeforeEach(func(ctx context.Context) {
					// Generate a complete DNSSEC chain: parent.example -> child.example -> www.child.example
					// This tests the full chain of trust validation with DS records
					var genErr error
					chainData, genErr = GenerateDNSSECChain("parent.", "child.parent.", "www.child.parent.", "192.0.2.30")
					Expect(genErr).Should(Succeed())

					// Format all records for mokka
					aRecordStr := FormatRecordForMokka(chainData.ARecord)
					aRRSIGStr := FormatRecordForMokka(chainData.ARRRSIG)
					childKeyStr := FormatRecordForMokka(chainData.ChildDNSKEY)
					childKeyRRSIGStr := FormatRecordForMokka(chainData.ChildDNSKEYRRSIG)
					dsStr := FormatRecordForMokka(chainData.DS)
					dsRRSIGStr := FormatRecordForMokka(chainData.DSRRSIG)
					parentKeyStr := FormatRecordForMokka(chainData.ParentDNSKEY)
					parentKeyRRSIGStr := FormatRecordForMokka(chainData.ParentDNSKEYRRSIG)

					// Create mokka with complete DNSSEC chain
					// Query responses:
					// 1. A www.child.parent -> A + RRSIG (signed by child)
					// 2. DNSKEY child.parent -> DNSKEY + DNSKEY_RRSIG (self-signed)
					// 3. DS child.parent -> DS + DS_RRSIG (DS signed by parent)
					// 4. DNSKEY parent -> DNSKEY + DNSKEY_RRSIG (self-signed, parent is trust anchor)
					_, err = createDNSMokkaContainer(ctx, "moka-dnssec-chain", e2eNet,
						fmt.Sprintf(`A www.child.parent/NOERROR("%s", "%s")`, aRecordStr, aRRSIGStr),
						fmt.Sprintf(`DNSKEY child.parent/NOERROR("%s", "%s")`, childKeyStr, childKeyRRSIGStr),
						fmt.Sprintf(`DS child.parent/NOERROR("%s", "%s")`, dsStr, dsRRSIGStr),
						fmt.Sprintf(`DNSKEY parent/NOERROR("%s", "%s")`, parentKeyStr, parentKeyRRSIGStr),
					)
					Expect(err).Should(Succeed())

					// Create blocky with parent DNSKEY as trust anchor
					// The validator should:
					// 1. Verify A record signature against child DNSKEY
					// 2. Verify child DNSKEY against DS record
					// 3. Verify DS record signature against parent DNSKEY
					// 4. Verify parent DNSKEY against trust anchor
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka-dnssec-chain",
						"dnssec:",
						"  validate: true",
						"  trustAnchors:",
						fmt.Sprintf("    - \"%s\"", chainData.ParentDNSKEY.String()),
						"log:",
						"  level: debug",
					)
					Expect(err).Should(Succeed())
				})

				It("should validate complete DNSSEC chain and set AD flag", func(ctx context.Context) {
					msg := util.NewMsgWithQuestion("www.child.parent.", A)
					msg.SetEdns0(4096, true) // Enable DNSSEC OK (DO) bit

					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Should return NOERROR because full DNSSEC chain validated successfully
					Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess),
						"Expected NOERROR for valid DNSSEC chain")

					// Should have the Authenticated Data (AD) flag set
					Expect(resp.AuthenticatedData).Should(BeTrue(),
						"AD flag should be set after successful chain of trust validation")

					// Should have the A record in the answer
					Expect(resp.Answer).Should(ContainElement(
						BeDNSRecord("www.child.parent.", A, "192.0.2.30"),
					))
				})
			})

			When("DNSSEC validation is disabled", func() {
				BeforeEach(func(ctx context.Context) {
					// Note: Using .example TLD instead of .test (SUDN resolver blocks .test)
					_, err = createDNSMokkaContainer(ctx, "moka-dnssec-disabled", e2eNet,
						`A any.domain.example/NOERROR("A 192.0.2.1 300")`,
					)
					Expect(err).Should(Succeed())

					blocky, err = createBlockyContainer(ctx, e2eNet,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka-dnssec-disabled",
						"# dnssec validation is disabled by default",
					)
					Expect(err).Should(Succeed())
				})

				It("should not validate DNSSEC and accept all responses", func(ctx context.Context) {
					msg := util.NewMsgWithQuestion("any.domain.example.", A)

					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// Should return NOERROR and the answer
					Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.Answer).Should(ContainElement(
						BeDNSRecord("any.domain.example.", A, "192.0.2.1"),
					))

					// AD flag should not be set when validation is disabled
					Expect(resp.AuthenticatedData).Should(BeFalse())
				})
			})
		})

		Describe("Issue #1287 - Independent DNSSEC validation", func() {
			When("upstream returns invalid DNSSEC data with CheckingDisabled flag", func() {
				BeforeEach(func(ctx context.Context) {
					// Use Google DNS - when queried with +cd flag, it returns data even for broken DNSSEC
					// With DNSSEC validation enabled, Blocky should independently validate and reject
					blocky, err = createBlockyContainer(ctx, e2eNet,
						"upstreams:",
						"  groups:",
						"    default:",
						"      - 8.8.8.8",
						"dnssec:",
						"  validate: true",
						"log:",
						"  level: debug",
					)
					Expect(err).Should(Succeed())
				})

				It("should independently validate and reject broken DNSSEC (Issue #1287 FIXED)", func(ctx context.Context) {
					// Query dnssec-failed.org with CheckingDisabled flag
					// This domain has intentionally broken DNSSEC signatures
					// Google DNS will return data when queried with +cd flag (CheckingDisabled)
					// But Blocky should independently validate and reject it
					msg := util.NewMsgWithQuestion("dnssec-failed.org.", A)
					msg.CheckingDisabled = true // +cd flag
					msg.SetEdns0(4096, true)    // DO bit

					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())

					// FIXED BEHAVIOR: Blocky validates independently regardless of upstream behavior
					// Should return SERVFAIL because DNSSEC validation failed
					Expect(resp.Rcode).Should(Equal(dns.RcodeServerFailure),
						"Blocky should validate independently and reject broken DNSSEC")

					// Should NOT have the Authenticated Data (AD) flag set
					Expect(resp.AuthenticatedData).Should(BeFalse(),
						"AD flag should not be set for failed DNSSEC validation")
				})
			})
		})
	})
})
