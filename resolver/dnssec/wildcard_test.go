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

			// No NSEC/NSEC3 records in authority section. RFC 4035 §5.3.4: the RRSIG of the wildcard
			// does not show that the wildcard answers for the name.
			err := sut.validateWildcardExpansion("sub.example.com.", rrsig, []dns.RR{}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
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

	Describe("isWildcardExpansion", func() {
		// RFC 4034 §3.1.3: the Labels field counts neither the root label nor a leading "*" label
		DescribeTable("compares the Labels field with the labels that an RRSIG for the owner name counts",
			func(owner string, labels uint8, expected bool) {
				Expect(isWildcardExpansion(owner, &dns.RRSIG{Labels: labels})).Should(Equal(expected))
			},
			Entry("a name with its own RRSIG", "sub.example.com.", uint8(3), false),
			Entry("a name that *.example.com. answers for", "sub.example.com.", uint8(2), true),
			Entry("a name below one that *.example.com. answers for", "a.sub.example.com.", uint8(2), true),
			Entry("the wildcard *.example.com. itself", "*.example.com.", uint8(2), false),
			Entry("the wildcard *.example.com. answered by *.com.", "*.example.com.", uint8(1), true),
			Entry("the wildcard of the root itself", "*.", uint8(0), false),
		)
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
			// Two records that cover the name, each with the salt of another chain
			nsec3_1 := nsec3SaltedRange("example.com.", "sub.example.com.", "aabbcc", 10, -1, 1)
			nsec3_2 := nsec3SaltedRange("example.com.", "sub.example.com.", "ddeeff", 10, -1, 1)

			err := sut.validateWildcardNSEC3([]*dns.NSEC3{nsec3_1, nsec3_2}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("inconsistent"))

			Expect(sut.validateWildcardNSEC3([]*dns.NSEC3{nsec3_1}, "sub.example.com.")).Should(Succeed())
		})

		It("should fail when iteration count exceeds maximum", func() {
			// Way over the limit
			nsec3 := nsec3SaltedRange("example.com.", "sub.example.com.", "aabbcc", 10000, -1, 1)

			err := sut.validateWildcardNSEC3([]*dns.NSEC3{nsec3}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("exceeds maximum"))
		})

		It("should ignore a record with another hash algorithm than SHA-1", func() {
			// RFC 5155 §8.1: such a record is no part of a proof, so the name has none
			nsec3 := nsec3SaltedRange("example.com.", "sub.example.com.", "aabbcc", 10, -1, 1)
			nsec3.Hash = 2

			err := sut.validateWildcardNSEC3([]*dns.NSEC3{nsec3}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("no NSEC3 record covers"))
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
			// RFC 4035 §5.3.4: a wildcard answers only for a name that is proven not to exist
			err := sut.validateWildcardProof("*.example.com.", "sub.example.com.", []dns.RR{}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
		})

		It("should fail with non-NSEC/NSEC3 records", func() {
			otherRR := &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA},
			}

			err := sut.validateWildcardProof("*.example.com.", "sub.example.com.", []dns.RR{otherRR}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
		})

		It("should take the proof from NSEC records and, if they do not give it, from NSEC3 records", func() {
			// RFC 5155 §10.4: a server answers with one of the chains of a zone, and each chain is a
			// signed statement of the zone. Each of these records gives the proof without the other.
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}
			nsec3 := nsec3Range("example.com.", "sub.example.com.", -1, 1)

			// An NSEC record that does not cover the name, and an NSEC3 record that does not cover
			// its hash
			otherNSEC := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "t.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}
			otherNSEC3 := nsec3Range("example.com.", "sub.example.com.", 1, 2)

			proof := func(records ...dns.RR) error {
				return sut.validateWildcardProof("*.example.com.", "sub.example.com.", records, "sub.example.com.")
			}

			Expect(proof(nsec)).Should(Succeed())
			Expect(proof(nsec3)).Should(Succeed())
			Expect(proof(nsec, nsec3)).Should(Succeed())
			Expect(proof(nsec, otherNSEC3)).Should(Succeed())
			Expect(proof(otherNSEC, nsec3)).Should(Succeed())
			Expect(proof(otherNSEC, otherNSEC3)).Should(HaveOccurred())
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
