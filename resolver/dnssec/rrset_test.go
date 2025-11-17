package dnssec

import (
	"context"
	"errors"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
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

	Describe("findMatchingRRSIGsForType", func() {
		It("should find matching RRSIG for type", func() {
			rrsigA := &dns.RRSIG{TypeCovered: dns.TypeA}
			rrsigAAAA := &dns.RRSIG{TypeCovered: dns.TypeAAAA}
			rrsigDNSKEY := &dns.RRSIG{TypeCovered: dns.TypeDNSKEY}

			sigs := []*dns.RRSIG{rrsigA, rrsigAAAA, rrsigDNSKEY}

			result := findMatchingRRSIGsForType(sigs, dns.TypeA)
			Expect(result).Should(HaveLen(1))
			Expect(result[0]).Should(Equal(rrsigA))
		})

		It("should return empty slice when no match", func() {
			rrsigAAAA := &dns.RRSIG{TypeCovered: dns.TypeAAAA}
			result := findMatchingRRSIGsForType([]*dns.RRSIG{rrsigAAAA}, dns.TypeA)
			Expect(result).Should(BeEmpty())
		})

		It("should return multiple matching RRSIGs", func() {
			rrsig1 := &dns.RRSIG{TypeCovered: dns.TypeA, Algorithm: dns.RSASHA256}
			rrsig2 := &dns.RRSIG{TypeCovered: dns.TypeA, Algorithm: dns.ED25519}

			result := findMatchingRRSIGsForType([]*dns.RRSIG{rrsig1, rrsig2}, dns.TypeA)
			Expect(result).Should(HaveLen(2))
		})

		It("should handle empty input", func() {
			result := findMatchingRRSIGsForType([]*dns.RRSIG{}, dns.TypeA)
			Expect(result).Should(BeEmpty())
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

			rrsig := &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG},
				TypeCovered: dns.TypeA,
				Algorithm:   dns.RSASHA256,
				Labels:      2,
				SignerName:  "example.com.",
				Inception:   uint32(time.Now().Add(2 * time.Hour).Unix()), // Future
				Expiration:  uint32(time.Now().Add(3 * time.Hour).Unix()),
			}

			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "test-key",
			}

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

			rrsig := &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG},
				TypeCovered: dns.TypeA,
				Algorithm:   dns.RSASHA256,
				Labels:      2,
				SignerName:  "example.com.",
				Inception:   uint32(time.Now().Add(-3 * time.Hour).Unix()),
				Expiration:  uint32(time.Now().Add(-2 * time.Hour).Unix()), // Past
			}

			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "test-key",
			}

			err := sut.verifyRRSIG(rrset, rrsig, key, nil, "example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("expired"))
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

	Describe("queryAndMatchDNSKEY", func() {
		It("should query and find matching DNSKEY", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 10)

			dnskey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256,
				PublicKey: "test-key",
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{dnskey},
					},
				}, nil
			}

			newCtx, key, err := sut.queryAndMatchDNSKEY(ctx, "example.com.", dnskey.KeyTag(), dnskey.Algorithm)
			Expect(err).Should(Succeed())
			Expect(key).Should(Equal(dnskey))
			Expect(newCtx).ShouldNot(BeNil())
		})

		It("should fail when DNSKEY with matching key tag not found", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 10)

			dnskey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256,
				PublicKey: "test-key",
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{dnskey},
					},
				}, nil
			}

			_, _, err := sut.queryAndMatchDNSKEY(ctx, "example.com.", 12345, dns.ECDSAP256SHA256) // Wrong key tag
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("no DNSKEY with key tag"))
		})

		It("should treat query failure as Bogus", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return nil, errors.New("query failed")
			}

			_, _, err := sut.queryAndMatchDNSKEY(ctx, "example.com.", 12345, dns.ECDSAP256SHA256)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("failed to query DNSKEY"))
		})
	})
})
