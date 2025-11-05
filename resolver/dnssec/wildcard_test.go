package dnssec

import (
	"github.com/0xERR0R/blocky/log"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Wildcard validation functions", func() {
	var (
		sut          *Validator
		trustStore   *TrustAnchorStore
		mockUpstream *mockResolver
	)

	BeforeEach(func(specCtx SpecContext) {
		var err error
		trustStore, err = NewTrustAnchorStore(nil)
		Expect(err).Should(Succeed())

		mockUpstream = &mockResolver{}
		logger, _ := log.NewMockEntry()

		sut = NewValidator(specCtx, trustStore, logger, mockUpstream, 1, 10, 150, 30, 3600)
	})

	Describe("validateWildcardExpansion", func() {
		It("should pass when not a wildcard (same label count)", func() {
			rrsig := &dns.RRSIG{
				Labels:     2, // example.com
				SignerName: "example.com.",
			}

			err := sut.validateWildcardExpansion("example.com.", rrsig, nil, "example.com.")
			Expect(err).Should(Succeed())
		})

		It("should pass when not a wildcard (fewer labels)", func() {
			rrsig := &dns.RRSIG{
				Labels:     3, // sub.example.com
				SignerName: "example.com.",
			}

			err := sut.validateWildcardExpansion("sub.example.com.", rrsig, nil, "sub.example.com.")
			Expect(err).Should(Succeed())
		})

		It("should validate wildcard when RRset has more labels than RRSIG", func() {
			rrsig := &dns.RRSIG{
				Labels:     2, // *.example.com -> 2 labels after wildcard
				SignerName: "example.com.",
			}

			// RRset has 3 labels, RRSIG says 2 -> wildcard expansion
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			err := sut.validateWildcardExpansion("sub.example.com.", rrsig, []dns.RR{nsec}, "sub.example.com.")
			Expect(err).Should(Succeed())
		})

		It("should fail when wildcard name not within signer zone", func() {
			rrsig := &dns.RRSIG{
				Labels:     2,
				SignerName: "other.com.", // Different zone
			}

			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			err := sut.validateWildcardExpansion("sub.example.com.", rrsig, []dns.RR{nsec}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("not within signer zone"))
		})

		It("should fail when no NSEC/NSEC3 proof provided", func() {
			rrsig := &dns.RRSIG{
				Labels:     2,
				SignerName: "example.com.",
			}

			// No NSEC/NSEC3 records in authority section
			err := sut.validateWildcardExpansion("sub.example.com.", rrsig, []dns.RR{}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("no NSEC/NSEC3 proof"))
		})

		It("should handle deeply nested wildcards", func() {
			rrsig := &dns.RRSIG{
				Labels:     3, // *.sub.example.com
				SignerName: "example.com.",
			}

			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.sub.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "zzz.sub.example.com.",
			}

			err := sut.validateWildcardExpansion("test.sub.example.com.", rrsig, []dns.RR{nsec}, "test.sub.example.com.")
			Expect(err).Should(Succeed())
		})
	})

	Describe("validateWildcardNSEC", func() {
		It("should validate when NSEC covers query name", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			err := sut.validateWildcardNSEC([]*dns.NSEC{nsec}, "sub.example.com.")
			Expect(err).Should(Succeed())
		})

		It("should fail when no NSEC covers query name", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "b.example.com.",
			}

			err := sut.validateWildcardNSEC([]*dns.NSEC{nsec}, "z.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("no NSEC record covers"))
		})

		It("should handle empty NSEC list", func() {
			err := sut.validateWildcardNSEC([]*dns.NSEC{}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
		})

		It("should normalize domain names", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			err := sut.validateWildcardNSEC([]*dns.NSEC{nsec}, "sub.example.com")
			Expect(err).Should(Succeed())
		})

		It("should check multiple NSEC records", func() {
			nsec1 := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "m.example.com.",
			}
			nsec2 := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "m.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			// Query covered by second NSEC
			err := sut.validateWildcardNSEC([]*dns.NSEC{nsec1, nsec2}, "n.example.com.")
			Expect(err).Should(Succeed())
		})
	})

	Describe("validateWildcardNSEC3", func() {
		It("should fail when no NSEC3 records provided", func() {
			err := sut.validateWildcardNSEC3([]*dns.NSEC3{}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("no NSEC3 records"))
		})

		It("should fail when NSEC3 parameters inconsistent", func() {
			nsec3_1 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "abc123.example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "aabbcc",
				Iterations: 10,
			}
			nsec3_2 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "def456.example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "ddeeff", // Different salt
				Iterations: 10,
			}

			err := sut.validateWildcardNSEC3([]*dns.NSEC3{nsec3_1, nsec3_2}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("inconsistent"))
		})

		It("should fail when iteration count exceeds maximum", func() {
			nsec3 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "abc123.example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "aabbcc",
				Iterations: 10000, // Way over the limit
			}

			err := sut.validateWildcardNSEC3([]*dns.NSEC3{nsec3}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("exceeds maximum"))
		})

		It("should fail for unsupported hash algorithm", func() {
			nsec3 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "abc123.example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       2, // Not SHA1
				Salt:       "aabbcc",
				Iterations: 10,
			}

			err := sut.validateWildcardNSEC3([]*dns.NSEC3{nsec3}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("unsupported"))
		})

		It("should normalize domain names", func() {
			nsec3 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "abc123.example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "zzz999",
			}

			// Will fail because hash won't match, but validates inputs
			err := sut.validateWildcardNSEC3([]*dns.NSEC3{nsec3}, "sub.example.com")
			Expect(err).Should(HaveOccurred())
		})
	})

	Describe("validateWildcardProof", func() {
		It("should use NSEC when available", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			err := sut.validateWildcardProof("*.example.com.", "sub.example.com.", []dns.RR{nsec}, "sub.example.com.")
			Expect(err).Should(Succeed())
		})

		It("should fail when neither NSEC nor NSEC3 available", func() {
			err := sut.validateWildcardProof("*.example.com.", "sub.example.com.", []dns.RR{}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("no NSEC/NSEC3 proof"))
		})

		It("should handle non-NSEC/NSEC3 records", func() {
			otherRR := &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA},
			}

			err := sut.validateWildcardProof("*.example.com.", "sub.example.com.", []dns.RR{otherRR}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
		})

		It("should prefer NSEC over NSEC3 when both present", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}
			nsec3 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "abc123.example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			// Should use NSEC and succeed
			err := sut.validateWildcardProof("*.example.com.", "sub.example.com.", []dns.RR{nsec, nsec3}, "sub.example.com.")
			Expect(err).Should(Succeed())
		})
	})

	Describe("validateWildcardExpansionDetails", func() {
		It("should fail when RRset has fewer labels than RRSIG claims", func() {
			err := sut.validateWildcardExpansionDetails("example.com.", "example.com.", 3, nil, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("invalid wildcard"))
		})

		It("should construct correct wildcard name", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			// sub.example.com with RRSIG labels=2 -> wildcard is *.example.com
			err := sut.validateWildcardExpansionDetails("sub.example.com.", "example.com.", 2, []dns.RR{nsec},
				"sub.example.com.")
			Expect(err).Should(Succeed())
		})

		It("should handle multi-level wildcards", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.sub.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "zzz.sub.example.com.",
			}

			// test.sub.example.com with RRSIG labels=3 -> wildcard is *.sub.example.com
			err := sut.validateWildcardExpansionDetails("test.sub.example.com.", "example.com.", 3, []dns.RR{nsec},
				"test.sub.example.com.")
			Expect(err).Should(Succeed())
		})
	})
})
