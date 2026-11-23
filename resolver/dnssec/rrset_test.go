package dnssec

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RRset validation functions", func() {
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

	Describe("getAlgorithmStrength", func() {
		It("should return highest strength for ED448", func() {
			strength := sut.getAlgorithmStrength(dns.ED448)
			Expect(strength).Should(Equal(algorithmStrengthED448))
		})

		It("should return very high strength for ED25519", func() {
			strength := sut.getAlgorithmStrength(dns.ED25519)
			Expect(strength).Should(Equal(algorithmStrengthED25519))
		})

		It("should return high strength for ECDSA algorithms", func() {
			strength1 := sut.getAlgorithmStrength(dns.ECDSAP384SHA384)
			strength2 := sut.getAlgorithmStrength(dns.ECDSAP256SHA256)
			Expect(strength1).Should(Equal(algorithmStrengthECDSAP384SHA384))
			Expect(strength2).Should(Equal(algorithmStrengthECDSAP256SHA256))
			Expect(strength1).Should(BeNumerically(">", strength2))
		})

		It("should return moderate strength for RSA algorithms", func() {
			strength1 := sut.getAlgorithmStrength(dns.RSASHA512)
			strength2 := sut.getAlgorithmStrength(dns.RSASHA256)
			Expect(strength1).Should(Equal(algorithmStrengthRSASHA512))
			Expect(strength2).Should(Equal(algorithmStrengthRSASHA256))
		})

		It("should return low strength for deprecated RSASHA1", func() {
			strength := sut.getAlgorithmStrength(dns.RSASHA1)
			Expect(strength).Should(Equal(algorithmStrengthRSASHA1))
		})

		It("should return zero for unsupported algorithms", func() {
			strength := sut.getAlgorithmStrength(255) // Invalid algorithm
			Expect(strength).Should(Equal(algorithmStrengthUnsupported))
		})

		It("should rank algorithms correctly", func() {
			// Verify ED448 > ED25519 > ECDSA > RSA > unsupported
			ed448 := sut.getAlgorithmStrength(dns.ED448)
			ed25519 := sut.getAlgorithmStrength(dns.ED25519)
			ecdsa := sut.getAlgorithmStrength(dns.ECDSAP256SHA256)
			rsa := sut.getAlgorithmStrength(dns.RSASHA256)
			unsupported := sut.getAlgorithmStrength(255)

			Expect(ed448).Should(BeNumerically(">", ed25519))
			Expect(ed25519).Should(BeNumerically(">", ecdsa))
			Expect(ecdsa).Should(BeNumerically(">", rsa))
			Expect(rsa).Should(BeNumerically(">", unsupported))
		})
	})

	Describe("selectBestRRSIG", func() {
		It("should return nil for empty list", func() {
			result := sut.selectBestRRSIG([]*dns.RRSIG{})
			Expect(result).Should(BeNil())
		})

		It("should return single RRSIG", func() {
			rrsig := &dns.RRSIG{Algorithm: dns.RSASHA256}
			result := sut.selectBestRRSIG([]*dns.RRSIG{rrsig})
			Expect(result).Should(Equal(rrsig))
		})

		It("should select strongest algorithm", func() {
			weak := &dns.RRSIG{Algorithm: dns.RSASHA256}
			strong := &dns.RRSIG{Algorithm: dns.ED25519}
			strongest := &dns.RRSIG{Algorithm: dns.ED448}

			result := sut.selectBestRRSIG([]*dns.RRSIG{weak, strong, strongest})
			Expect(result).Should(Equal(strongest))
		})

		It("should prefer ED25519 over RSASHA256", func() {
			rsa := &dns.RRSIG{Algorithm: dns.RSASHA256}
			ed := &dns.RRSIG{Algorithm: dns.ED25519}

			result := sut.selectBestRRSIG([]*dns.RRSIG{rsa, ed})
			Expect(result).Should(Equal(ed))
		})

		It("should handle multiple RRSIGs with same algorithm", func() {
			rrsig1 := &dns.RRSIG{Algorithm: dns.RSASHA256, KeyTag: 1}
			rrsig2 := &dns.RRSIG{Algorithm: dns.RSASHA256, KeyTag: 2}

			result := sut.selectBestRRSIG([]*dns.RRSIG{rrsig1, rrsig2})
			Expect(result).Should(Equal(rrsig1)) // Returns first one
		})

		It("should prevent algorithm downgrade attacks", func() {
			// Attacker provides weak algorithm first
			weak := &dns.RRSIG{Algorithm: dns.RSASHA1}
			strong := &dns.RRSIG{Algorithm: dns.ED25519}

			result := sut.selectBestRRSIG([]*dns.RRSIG{weak, strong})
			Expect(result).Should(Equal(strong)) // Must select stronger
		})
	})

	Describe("validateSignerName", func() {
		It("should accept signer equal to RRset name", func() {
			result := validateSignerName("example.com.", "example.com.")
			Expect(result).Should(BeTrue())
		})

		It("should accept signer as parent of RRset name", func() {
			result := validateSignerName("example.com.", "sub.example.com.")
			Expect(result).Should(BeTrue())
		})

		It("should accept root as signer for any domain", func() {
			result := validateSignerName(".", "example.com.")
			Expect(result).Should(BeTrue())
		})

		It("should reject signer as child of RRset name", func() {
			result := validateSignerName("sub.example.com.", "example.com.")
			Expect(result).Should(BeFalse())
		})

		It("should reject unrelated signer", func() {
			result := validateSignerName("other.com.", "example.com.")
			Expect(result).Should(BeFalse())
		})

		It("should handle case insensitivity", func() {
			result := validateSignerName("EXAMPLE.COM.", "example.com.")
			Expect(result).Should(BeTrue())
		})
	})

	Describe("findMatchingDNSKEY", func() {
		It("should find key with matching key tag", func() {
			key1 := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256,
				PublicKey: "key1",
			}
			key2 := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY},
				Flags:     256,
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256,
				PublicKey: "key2",
			}

			keys := []*dns.DNSKEY{key1, key2}
			result := findMatchingDNSKEY(keys, key1.KeyTag(), key1.Algorithm)
			Expect(result).Should(Equal(key1))
		})

		It("should return nil when no match", func() {
			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256,
				PublicKey: "key1",
			}

			result := findMatchingDNSKEY([]*dns.DNSKEY{key}, 12345, dns.ECDSAP256SHA256)
			Expect(result).Should(BeNil())
		})

		It("should handle empty key list", func() {
			result := findMatchingDNSKEY([]*dns.DNSKEY{}, 12345, dns.ECDSAP256SHA256)
			Expect(result).Should(BeNil())
		})

		It("should skip revoked keys", func() {
			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY},
				Flags:     257 | 0x0080, // KSK with REVOKE flag
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256,
				PublicKey: "key1",
			}

			Expect(findMatchingDNSKEY([]*dns.DNSKEY{key}, key.KeyTag(), key.Algorithm)).Should(BeNil())
		})
	})

	Describe("isSupportedAlgorithm", func() {
		It("should support RSASHA1", func() {
			Expect(sut.isSupportedAlgorithm(dns.RSASHA1)).Should(BeTrue())
		})

		It("should support RSASHA256", func() {
			Expect(sut.isSupportedAlgorithm(dns.RSASHA256)).Should(BeTrue())
		})

		It("should support RSASHA512", func() {
			Expect(sut.isSupportedAlgorithm(dns.RSASHA512)).Should(BeTrue())
		})

		It("should support ECDSAP256SHA256", func() {
			Expect(sut.isSupportedAlgorithm(dns.ECDSAP256SHA256)).Should(BeTrue())
		})

		It("should support ECDSAP384SHA384", func() {
			Expect(sut.isSupportedAlgorithm(dns.ECDSAP384SHA384)).Should(BeTrue())
		})

		It("should support ED25519", func() {
			Expect(sut.isSupportedAlgorithm(dns.ED25519)).Should(BeTrue())
		})

		It("should support ED448", func() {
			Expect(sut.isSupportedAlgorithm(dns.ED448)).Should(BeTrue())
		})

		It("should reject unsupported algorithms", func() {
			Expect(sut.isSupportedAlgorithm(0)).Should(BeFalse())
			Expect(sut.isSupportedAlgorithm(255)).Should(BeFalse())
		})
	})

	Describe("verifyRRSIG", func() {
		It("should reject unsupported algorithms", func() {
			rrset := []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: []byte{192, 0, 2, 1},
				},
			}

			rrsig := &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG},
				TypeCovered: dns.TypeA,
				Algorithm:   255, // Unsupported
				Labels:      2,
				SignerName:  "example.com.",
				Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
				Expiration:  uint32(time.Now().Add(1 * time.Hour).Unix()),
			}

			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY},
				Flags:     257,
				Protocol:  3,
				Algorithm: 255,
				PublicKey: "test-key",
			}

			err := sut.verifyRRSIG(rrset, rrsig, key, nil, "example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("unsupported"))
		})

		It("should reject algorithm mismatch between RRSIG and DNSKEY", func() {
			rrset := []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: []byte{192, 0, 2, 1},
				},
			}

			rrsig := &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG},
				TypeCovered: dns.TypeA,
				Algorithm:   dns.RSASHA256,
				Labels:      2,
				SignerName:  "example.com.",
				Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
				Expiration:  uint32(time.Now().Add(1 * time.Hour).Unix()),
			}

			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256, // Different algorithm
				PublicKey: "test-key",
			}

			err := sut.verifyRRSIG(rrset, rrsig, key, nil, "example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("algorithm mismatch"))
		})

		It("should reject signature not yet valid (before inception)", func() {
			rrset := []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: []byte{192, 0, 2, 1},
				},
			}

			// The key made the signature, for a validity period in the future: only a signature that
			// verifies is refused for its dates
			key, priv, _ := newSignedZoneKey("example.com.")
			rrsig := signRRsetDuring(rrset, dns.TypeA, key, priv, "example.com.", 2*time.Hour, 3*time.Hour)

			err := sut.verifyRRSIG(rrset, rrsig, key, nil, "example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("not yet valid"))
		})

		It("should reject expired signature", func() {
			rrset := []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: []byte{192, 0, 2, 1},
				},
			}

			// The key made the signature, for a validity period in the past
			key, priv, _ := newSignedZoneKey("example.com.")
			rrsig := signRRsetDuring(rrset, dns.TypeA, key, priv, "example.com.", -3*time.Hour, -2*time.Hour)

			err := sut.verifyRRSIG(rrset, rrsig, key, nil, "example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("expired"))

			// A signature that the key did not make is a failed signature, whatever its dates
			rrsig.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))

			err = sut.verifyRRSIG(rrset, rrsig, key, nil, "example.com.")
			Expect(err).Should(MatchError(errRRSIGVerificationFailed))
			Expect(err.Error()).ShouldNot(ContainSubstring("expired"))
		})

		It("should apply clock skew tolerance", func() {
			// With default 3600s tolerance, signature slightly in the future should be accepted
			rrset := []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: []byte{192, 0, 2, 1},
				},
			}

			rrsig := &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG},
				TypeCovered: dns.TypeA,
				Algorithm:   dns.RSASHA256,
				Labels:      2,
				SignerName:  "example.com.",
				Inception:   uint32(time.Now().Add(30 * time.Minute).Unix()), // Within tolerance
				Expiration:  uint32(time.Now().Add(2 * time.Hour).Unix()),
			}

			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "test-key",
			}

			err := sut.verifyRRSIG(rrset, rrsig, key, nil, "example.com.")
			// Will fail on crypto but not on timing
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).ShouldNot(ContainSubstring("not yet valid"))
		})
	})

	Describe("verifyWithZoneKeys", func() {
		var (
			key    *dns.DNSKEY
			priv   *ecdsa.PrivateKey
			rrset  []dns.RR
			budget int
		)

		BeforeEach(func() {
			key, priv, _ = newSignedZoneKey("example.com.")
			rrset = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{192, 0, 2, 1},
			}}
			budget = maxZoneKeyVerifications
		})

		It("should verify an RRset signed by one of the keys", func() {
			otherKey, _, _ := newSignedZoneKey("example.com.")
			sig := signRRset(rrset, dns.TypeA, key, priv, "example.com.")

			Expect(sut.verifyWithZoneKeys(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{otherKey, key}, &budget)).
				Should(Succeed())
		})

		It("should reject a signature made by a key outside the set", func() {
			otherKey, _, _ := newSignedZoneKey("example.com.")
			for otherKey.KeyTag() == key.KeyTag() {
				otherKey, _, _ = newSignedZoneKey("example.com.")
			}
			sig := signRRset(rrset, dns.TypeA, key, priv, "example.com.")

			Expect(sut.verifyWithZoneKeys(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{otherKey}, &budget)).
				Should(MatchError(ContainSubstring("no RRSIG made by a validated key")))
		})

		It("should try every key that has the key tag of the signature", func() {
			// Swapping two public key bytes an even distance apart keeps the key tag checksum
			// (RFC 4034 Appendix B) and breaks the key.
			pub, err := base64.StdEncoding.DecodeString(key.PublicKey)
			Expect(err).Should(Succeed())
			i := 0
			for pub[i] == pub[i+2] {
				i++
			}
			pub[i], pub[i+2] = pub[i+2], pub[i]
			sameTag := *key
			sameTag.PublicKey = base64.StdEncoding.EncodeToString(pub)
			Expect(sameTag.KeyTag()).Should(Equal(key.KeyTag()))
			sig := signRRset(rrset, dns.TypeA, key, priv, "example.com.")

			Expect(sut.verifyWithZoneKeys(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{&sameTag, key}, &budget)).
				Should(Succeed())
			Expect(budget).Should(Equal(maxZoneKeyVerifications-2), "both keys were tried")
		})

		It("should stop after a bounded number of failed verifications", func() {
			sig := signRRset(rrset, dns.TypeA, key, priv, "example.com.")
			sig.Signature = signRRset([]dns.RR{key}, dns.TypeDNSKEY, key, priv, "example.com.").Signature

			sigs := make([]*dns.RRSIG, 100)
			for i := range sigs {
				sigs[i] = sig
			}

			err := sut.verifyWithZoneKeys(rrset, sigs, []*dns.DNSKEY{key}, &budget)
			Expect(err).Should(MatchError(ContainSubstring("signature verification failed")))
			Expect(strings.Count(err.Error(), "signature verification failed")).Should(Equal(maxZoneKeyVerifications))
		})
	})

	Describe("verifyWithKeys", func() {
		It("should not try a key that the signer of the RRSIG does not own", func(ctx SpecContext) {
			budget := maxZoneKeyVerifications

			// A 2^32+1 key verifies through math/big, which checks the signature and nothing else
			key, _, n, d := generateBigExponentRSAKey("example.com.")
			rrset := []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{192, 0, 2, 1},
			}}
			sig := signRRsetWithBigExponent(rrset, dns.TypeA, key, n, d)

			// The same key as a key of another zone
			other := *key
			other.Hdr.Name = "example.org."

			Expect(sut.verifyWithKeys(ctx, rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, &budget)).Should(BeIdenticalTo(sig))

			verified, err := sut.verifyWithKeys(ctx, rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{&other}, &budget)
			Expect(err).Should(HaveOccurred())
			Expect(verified).Should(BeNil())
		})
	})

	Describe("verifyRRset", func() {
		It("should verify no more signatures than the budget of the validation holds", func(ctx SpecContext) {
			key, priv, _ := newSignedZoneKey("example.com.")
			keys := []*dns.DNSKEY{key}
			rrset := []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{192, 0, 2, 1},
			}}
			sigs := []*dns.RRSIG{signRRset(rrset, dns.TypeA, key, priv, "example.com.")}

			// Every RRset has its own tries, and all of them share the budget of their validation
			validation := withQueryBudget(ctx, 1)

			for range maxVerifications {
				r := newRRsetResult(rrset)
				Expect(sut.verifyRRset(validation, &r, sigs, newKeySet(validation, keys))).Should(BeIdenticalTo(sigs[0]))
			}

			r := newRRsetResult(rrset)
			_, err := sut.verifyRRset(validation, &r, sigs, newKeySet(validation, keys))
			Expect(err).Should(MatchError(errBudgetExhausted))
			Expect(budgetFrom(validation).verifications.Load()).Should(BeEquivalentTo(maxVerifications))

			// A validation that has run out asks for nothing more either
			Expect(sut.consumeQueryBudget(validation)).Should(MatchError(errBudgetExhausted))
		})

		It("should verify nothing once the validation has run out of NSEC3 hashes", func(ctx SpecContext) {
			key, priv, _ := newSignedZoneKey("example.com.")
			rrset := []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{192, 0, 2, 1},
			}}
			sigs := []*dns.RRSIG{signRRset(rrset, dns.TypeA, key, priv, "example.com.")}
			validation := withQueryBudget(ctx, 0)

			for i := range maxNSEC3Hashes + 1 {
				budgetFrom(validation).nsec3Hash(fmt.Sprintf("n%d.example.", i), "", 0)
			}

			r := newRRsetResult(rrset)
			_, err := sut.verifyRRset(validation, &r, sigs, newKeySet(validation, []*dns.DNSKEY{key}))
			Expect(err).Should(MatchError(errBudgetExhausted))
			Expect(budgetFrom(validation).verifications.Load()).Should(BeZero())
		})

		It("should verify a signature outside its validity period, on the budget like any other", func(ctx SpecContext) {
			key, priv, _ := newSignedZoneKey("example.com.")
			rrset := []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{192, 0, 2, 1},
			}}
			expired := signRRsetDuring(rrset, dns.TypeA, key, priv, "example.com.", -3*time.Hour, -2*time.Hour)
			validation := withQueryBudget(ctx, 0)

			r := newRRsetResult(rrset)
			_, err := sut.verifyRRset(validation, &r, []*dns.RRSIG{expired}, newKeySet(validation, []*dns.DNSKEY{key}))
			Expect(err).Should(MatchError(ContainSubstring("signature expired")))
			Expect(r.tries).Should(Equal(1))
			Expect(budgetFrom(validation).verifications.Load()).Should(BeEquivalentTo(1))
		})

		It("should verify nothing in a context that has no budget", func(ctx SpecContext) {
			key, priv, _ := newSignedZoneKey("example.com.")
			rrset := []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{192, 0, 2, 1},
			}}
			sigs := []*dns.RRSIG{signRRset(rrset, dns.TypeA, key, priv, "example.com.")}

			// Only withQueryBudget makes the context of a validation
			Expect(budgetFrom(ctx)).Should(BeNil())

			r := newRRsetResult(rrset)
			_, err := sut.verifyRRset(ctx, &r, sigs, newKeySet(ctx, []*dns.DNSKEY{key}))
			Expect(err).Should(MatchError(errNoBudget))
			Expect(budgetFrom(ctx).nsec3Hash("example.com.", "", 0)).Should(BeEmpty())
		})
	})

	Describe("checkRRSIG", func() {
		DescribeTable("verifies with an RSA key whose exponent is at most 2^32+1",
			func(ctx SpecContext, e *big.Int, verifies bool) {
				// The time that a verification takes grows with the length of the exponent. BIND 9 takes
				// exponents up to 2^32+1 too.
				key, _, n, d := generateRSAKeyWithExponent("example.com.", e)
				rrset := []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   []byte{192, 0, 2, 1},
				}}
				sig := signRRsetWithBigExponent(rrset, dns.TypeA, key, n, d)

				Expect(canVerifyWith(key)).Should(Equal(verifies))

				if verifies {
					Expect(sut.checkRRSIG(ctx, rrset, sig, key)).Should(Succeed())
				} else {
					Expect(sut.checkRRSIG(ctx, rrset, sig, key)).
						Should(MatchError(ContainSubstring("no support for the RSA exponent")))
				}
			},
			Entry("2^32+1", new(big.Int).SetUint64(1<<32+1), true),
			Entry("2^32+3", new(big.Int).SetUint64(1<<32+3), false),
			Entry("an exponent of 4096 bits", new(big.Int).SetBit(new(big.Int).Lsh(big.NewInt(1), 4095), 0, 1), false),
		)

		It("refuses an RRSIG that counts more labels than its owner name has (RFC 4035 §5.3.1)", func(ctx SpecContext) {
			rrset := []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{192, 0, 2, 1},
			}}

			// With either of the two verifications: that of miekg/dns, and that for an RSA exponent
			// which Go's crypto/rsa cannot load. The signature is one over the Labels field as it is.
			bigKey, _, n, d := generateBigExponentRSAKey("example.com.")
			bigSig := signRRsetWithBigExponent(rrset, dns.TypeA, bigKey, n, d)
			Expect(sut.checkRRSIG(ctx, rrset, bigSig, bigKey)).Should(Succeed())

			bigSig.Labels++
			signWithBigExponent(rrset, bigSig, n, d)
			Expect(sut.checkRRSIG(ctx, rrset, bigSig, bigKey)).Should(MatchError(ContainSubstring("more than its owner name")))

			key, priv, _ := newSignedZoneKey("example.com.")
			sig := signRRset(rrset, dns.TypeA, key, priv, "example.com.")
			Expect(sut.checkRRSIG(ctx, rrset, sig, key)).Should(Succeed())

			sig.Labels++
			Expect(sut.checkRRSIG(ctx, rrset, sig, key)).Should(MatchError(ContainSubstring("more than its owner name")))
		})

		It("does not count a leading \"*\" label of the owner name (RFC 4034 §3.1.3)", func(ctx SpecContext) {
			// The RRSIG of the records that a wildcard owns counts the labels below the "*"
			rrset := []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "*.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{192, 0, 2, 1},
			}}

			key, priv, _ := newSignedZoneKey("example.com.")
			sig := signRRset(rrset, dns.TypeA, key, priv, "example.com.")
			Expect(sig.Labels).Should(BeEquivalentTo(2))
			Expect(sut.checkRRSIG(ctx, rrset, sig, key)).Should(Succeed())

			sig.Labels++
			Expect(sut.checkRRSIG(ctx, rrset, sig, key)).Should(MatchError(ContainSubstring("more than its owner name")))
		})
	})
})
