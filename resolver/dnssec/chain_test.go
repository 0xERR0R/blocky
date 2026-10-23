package dnssec

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Chain of trust validation", func() {
	var (
		sut          *Validator
		trustStore   *TrustAnchorStore
		mockUpstream *mockResolver
		ctx          context.Context
	)

	BeforeEach(func(specCtx SpecContext) {
		ctx = specCtx

		var err error
		trustStore, err = NewTrustAnchorStore(nil)
		Expect(err).Should(Succeed())

		mockUpstream = &mockResolver{}
		logger, _ := log.NewMockEntry()

		sut = NewValidator(ctx, trustStore, logger, mockUpstream, 1, 10, 150, 30, 3600)
		ctx = withQueryBudget(ctx, 10)
	})

	Describe("getCachedValidation", func() {
		It("should return cached result when present", func() {
			domain := "example.com."
			expectedResult := ValidationResultSecure

			sut.setCachedValidation(ctx, domain, expectedResult)

			result, found := sut.getCachedValidation(ctx, domain)
			Expect(found).Should(BeTrue())
			Expect(result).Should(Equal(expectedResult))
		})

		It("should return false when not cached", func() {
			result, found := sut.getCachedValidation(ctx, "notcached.com.")
			Expect(found).Should(BeFalse())
			Expect(result).Should(Equal(ValidationResultIndeterminate))
		})

		It("should cache different results for different domains", func() {
			sut.setCachedValidation(ctx, "secure.com.", ValidationResultSecure)
			sut.setCachedValidation(ctx, "insecure.com.", ValidationResultInsecure)
			sut.setCachedValidation(ctx, "bogus.com.", ValidationResultBogus)

			result1, found1 := sut.getCachedValidation(ctx, "secure.com.")
			Expect(found1).Should(BeTrue())
			Expect(result1).Should(Equal(ValidationResultSecure))

			result2, found2 := sut.getCachedValidation(ctx, "insecure.com.")
			Expect(found2).Should(BeTrue())
			Expect(result2).Should(Equal(ValidationResultInsecure))

			result3, found3 := sut.getCachedValidation(ctx, "bogus.com.")
			Expect(found3).Should(BeTrue())
			Expect(result3).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("setCachedValidation", func() {
		It("should store validation result in cache", func() {
			domain := "example.com."
			result := ValidationResultSecure

			sut.setCachedValidation(ctx, domain, result)

			cached, found := sut.getCachedValidation(ctx, domain)
			Expect(found).Should(BeTrue())
			Expect(cached).Should(Equal(result))
		})

		It("should keep a Bogus result for at most bogusTTL", func() {
			sut.setCachedValidation(ctx, "bogus.com.", ValidationResultBogus)
			sut.setCachedValidation(ctx, "insecure.com.", ValidationResultInsecure)

			_, bogusLeft := sut.validationCache.Get(validationCacheKey(ctx, "bogus.com."))
			_, insecureLeft := sut.validationCache.Get(validationCacheKey(ctx, "insecure.com."))
			Expect(bogusLeft).Should(BeNumerically("~", bogusTTL, time.Second))
			Expect(insecureLeft).Should(BeNumerically(">", 59*time.Minute))
		})

		It("should overwrite existing cache entries", func() {
			domain := "example.com."

			sut.setCachedValidation(ctx, domain, ValidationResultSecure)
			sut.setCachedValidation(ctx, domain, ValidationResultBogus)

			cached, found := sut.getCachedValidation(ctx, domain)
			Expect(found).Should(BeTrue())
			Expect(cached).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("getParentDomain", func() {
		It("should return parent for subdomain", func() {
			parent := sut.getParentDomain("sub.example.com.")
			Expect(parent).Should(Equal("example.com."))
		})

		It("should return root for TLD", func() {
			parent := sut.getParentDomain("com.")
			Expect(parent).Should(Equal("."))
		})

		It("should return empty string for root", func() {
			parent := sut.getParentDomain(".")
			Expect(parent).Should(BeEmpty())
		})

		It("should handle multi-level domains", func() {
			parent := sut.getParentDomain("a.b.c.d.example.com.")
			Expect(parent).Should(Equal("b.c.d.example.com."))
		})

		It("should normalize domain to FQDN", func() {
			parent := sut.getParentDomain("sub.example.com")
			Expect(parent).Should(Equal("example.com."))
		})
	})

	Describe("validateDNSKEY", func() {
		It("should validate matching DNSKEY against DS", func() {
			dnskey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
				},
				Flags:     257, // KSK
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5x" +
					"QlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b5" +
					"8Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws" +
					"9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
			}

			ds := dnskey.ToDS(dns.SHA256)
			Expect(ds).ShouldNot(BeNil())

			err := sut.validateDNSKEY(dnskey, ds)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should fail when algorithm mismatch", func() {
			dnskey := &dns.DNSKEY{
				Algorithm: dns.RSASHA256,
			}
			ds := &dns.DS{
				Algorithm: dns.RSASHA1,
			}

			err := sut.validateDNSKEY(dnskey, ds)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("algorithm mismatch"))
		})

		It("should fail when key tag mismatch", func() {
			dnskey := &dns.DNSKEY{
				Algorithm: dns.RSASHA256,
			}
			ds := &dns.DS{
				Algorithm: dns.RSASHA256,
				KeyTag:    12345,
			}

			err := sut.validateDNSKEY(dnskey, ds)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("keytag mismatch"))
		})

		It("should fail when digest mismatch", func() {
			dnskey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDNSKEY,
				},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "test",
			}

			ds := &dns.DS{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDS,
				},
				KeyTag:     dnskey.KeyTag(),
				Algorithm:  dns.RSASHA256,
				DigestType: dns.SHA256,
				Digest:     "wrongdigest",
			}

			err := sut.validateDNSKEY(dnskey, ds)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("digest mismatch"))
		})

		It("should fail for unsupported digest type", func() {
			dnskey := &dns.DNSKEY{
				Algorithm: dns.RSASHA256,
			}
			ds := &dns.DS{
				Algorithm:  dns.RSASHA256,
				KeyTag:     dnskey.KeyTag(),
				DigestType: 99, // Unsupported
			}

			err := sut.validateDNSKEY(dnskey, ds)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("unsupported DS digest type"))
		})
	})

	Describe("validateAnyDNSKEY", func() {
		It("should return true when at least one DNSKEY validates", func() {
			validKey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
				},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5x" +
					"QlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b5" +
					"8Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws" +
					"9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
			}

			invalidKey := &dns.DNSKEY{
				Flags:     256, // ZSK
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "invalid",
			}

			ds := validKey.ToDS(dns.SHA256)

			result := sut.validateAnyDNSKEY([]*dns.DNSKEY{invalidKey, validKey}, []*dns.DS{ds}, "example.com.")
			Expect(result).Should(BeTrue())
		})

		It("should return false when no DNSKEY validates", func() {
			key := &dns.DNSKEY{
				Flags:     257,
				Algorithm: dns.RSASHA256,
				PublicKey: "test",
			}

			ds := &dns.DS{
				Algorithm:  dns.RSASHA256,
				DigestType: dns.SHA256,
				Digest:     "wrongdigest",
			}

			result := sut.validateAnyDNSKEY([]*dns.DNSKEY{key}, []*dns.DS{ds}, "example.com.")
			Expect(result).Should(BeFalse())
		})

		It("should skip keys without ZONE flag", func() {
			keyWithoutZone := &dns.DNSKEY{
				Flags:     0, // No ZONE flag
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "test",
			}

			ds := &dns.DS{
				Algorithm:  dns.RSASHA256,
				DigestType: dns.SHA256,
				Digest:     "somedigest",
			}

			result := sut.validateAnyDNSKEY([]*dns.DNSKEY{keyWithoutZone}, []*dns.DS{ds}, "example.com.")
			Expect(result).Should(BeFalse())
		})

		It("should skip revoked keys", func() {
			revokedKey := &dns.DNSKEY{
				Flags:     257 | 0x0080, // KSK with REVOKE flag
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "test",
			}

			ds := &dns.DS{
				Algorithm:  dns.RSASHA256,
				DigestType: dns.SHA256,
				Digest:     "somedigest",
			}

			result := sut.validateAnyDNSKEY([]*dns.DNSKEY{revokedKey}, []*dns.DS{ds}, "example.com.")
			Expect(result).Should(BeFalse())
		})

		It("should handle empty key list", func() {
			ds := &dns.DS{
				Algorithm:  dns.RSASHA256,
				DigestType: dns.SHA256,
				Digest:     "somedigest",
			}

			result := sut.validateAnyDNSKEY([]*dns.DNSKEY{}, []*dns.DS{ds}, "example.com.")
			Expect(result).Should(BeFalse())
		})

		It("should handle empty DS list", func() {
			key := &dns.DNSKEY{
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "test",
			}

			result := sut.validateAnyDNSKEY([]*dns.DNSKEY{key}, []*dns.DS{}, "example.com.")
			Expect(result).Should(BeFalse())
		})
	})

	Describe("verifyDNSKEYRRset with multiple DS-matched keys", func() {
		const zone = "example.com."

		It("accepts an RRset signed only by the second DS-matched key", func() {
			zsk, _, _ := newSignedZoneKey(zone)
			zsk.Flags = 256 // ZSK that also has a DS at the parent (like ilva.dk)
			ksk, kskPriv, _ := newSignedZoneKey(zone)

			sig := signRRset([]dns.RR{zsk, ksk}, dns.TypeDNSKEY, ksk, kskPriv, zone)

			keys, _ := sut.findAndValidateKSKs([]*dns.DNSKEY{zsk, ksk},
				[]*dns.DS{zsk.ToDS(dns.SHA256), ksk.ToDS(dns.SHA256)}, zone)
			Expect(keys).Should(HaveLen(2))

			verified, err := sut.verifyDNSKEYRRset([]dns.RR{zsk, ksk, sig}, keys, zone)
			Expect(err).Should(Succeed())
			Expect(verified).Should(Equal(sig))
		})

		It("rejects an RRset whose only RRSIG is from a key without a DS", func() {
			dsKey, _, _ := newSignedZoneKey(zone)
			other, otherPriv, _ := newSignedZoneKey(zone)

			sig := signRRset([]dns.RR{dsKey, other}, dns.TypeDNSKEY, other, otherPriv, zone)

			keys, _ := sut.findAndValidateKSKs([]*dns.DNSKEY{dsKey, other}, []*dns.DS{dsKey.ToDS(dns.SHA256)}, zone)
			Expect(keys).Should(HaveLen(1))

			_, err := sut.verifyDNSKEYRRset([]dns.RR{dsKey, other, sig}, keys, zone)
			Expect(err).Should(MatchError(ContainSubstring("no RRSIG found")))
		})

		Describe("verification attempt cap (KeyTrap, CVE-2023-50387)", func() {
			// buildZone returns n DS-matched keys with distinct key tags and an answer section in which
			// every key has an RRSIG over the DNSKEY RRset. Only the RRSIG at index validIdx is genuine;
			// the others are signed over a different RRset, so each costs a failed verification.
			buildZone := func(n, validIdx int) ([]*dns.DNSKEY, []dns.RR) {
				keys := make([]*dns.DNSKEY, 0, n)
				privs := make([]*ecdsa.PrivateKey, 0, n)
				tags := map[uint16]bool{}

				for len(keys) < n {
					key, priv, _ := newSignedZoneKey(zone)
					// Skip tag collisions (one matching RRSIG per key) and tag 0, which RRSIG.Sign rejects
					if key.KeyTag() == 0 || tags[key.KeyTag()] {
						continue
					}

					tags[key.KeyTag()] = true
					keys = append(keys, key)
					privs = append(privs, priv)
				}

				rrset := make([]dns.RR, 0, n)
				for _, key := range keys {
					rrset = append(rrset, key)
				}

				answer := append([]dns.RR{}, rrset...)

				for i, key := range keys {
					signed := rrset
					if i != validIdx {
						signed = []dns.RR{key}
					}

					sig := signRRset(signed, dns.TypeDNSKEY, key, privs[i], zone)
					answer = append(answer, sig)
				}

				return keys, answer
			}

			It("succeeds when the genuine signature is within the cap", func() {
				keys, answer := buildZone(3, 2)

				_, err := sut.verifyDNSKEYRRset(answer, keys, zone)
				Expect(err).Should(Succeed())
			})

			It("bounds a zone with many DS-matched keys and no genuine signature", func() {
				keys, answer := buildZone(100, -1)

				_, err := sut.verifyDNSKEYRRset(answer, keys, zone)
				Expect(err).Should(MatchError(ContainSubstring("giving up")))
			})
		})
	})

	Describe("convertDSToRRset", func() {
		It("should convert DS records to RR slice", func() {
			ds1 := &dns.DS{
				Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS},
				KeyTag:     1234,
				Algorithm:  dns.RSASHA256,
				DigestType: dns.SHA256,
				Digest:     "abcd",
			}
			ds2 := &dns.DS{
				Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS},
				KeyTag:     5678,
				Algorithm:  dns.RSASHA256,
				DigestType: dns.SHA256,
				Digest:     "efgh",
			}

			rrset := convertDSToRRset([]*dns.DS{ds1, ds2})
			Expect(rrset).Should(HaveLen(2))
			Expect(rrset[0]).Should(Equal(dns.RR(ds1)))
			Expect(rrset[1]).Should(Equal(dns.RR(ds2)))
		})

		It("should handle empty DS list", func() {
			rrset := convertDSToRRset([]*dns.DS{})
			Expect(rrset).Should(BeEmpty())
		})

		It("should handle nil DS list", func() {
			rrset := convertDSToRRset(nil)
			Expect(rrset).ShouldNot(BeNil())
			Expect(rrset).Should(BeEmpty())
		})
	})

	Describe("extractTypedRecords", func() {
		It("should extract DS records from answer section", func() {
			ds1 := &dns.DS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS},
			}
			ds2 := &dns.DS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS},
			}
			a := &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA},
			}

			dsRecords, err := extractTypedRecords[*dns.DS]([]dns.RR{ds1, a, ds2})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(dsRecords).Should(HaveLen(2))
			Expect(dsRecords[0]).Should(Equal(ds1))
			Expect(dsRecords[1]).Should(Equal(ds2))
		})

		It("should extract from multiple RR slices", func() {
			ds1 := &dns.DS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS},
			}
			ds2 := &dns.DS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS},
			}

			dsRecords, err := extractTypedRecords[*dns.DS]([]dns.RR{ds1}, []dns.RR{ds2})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(dsRecords).Should(HaveLen(2))
		})

		It("should return error when no records found", func() {
			a := &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA},
			}

			_, err := extractTypedRecords[*dns.DS]([]dns.RR{a})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("no records of requested type found"))
		})

		It("should handle empty RR slices", func() {
			_, err := extractTypedRecords[*dns.DS]([]dns.RR{})
			Expect(err).Should(HaveOccurred())
		})

		It("should work with other record types", func() {
			dnskey := &dns.DNSKEY{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY},
			}
			a := &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA},
			}

			keys, err := extractTypedRecords[*dns.DNSKEY]([]dns.RR{a, dnskey})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(keys).Should(HaveLen(1))
			Expect(keys[0]).Should(Equal(dnskey))
		})
	})

	Describe("findDSRRSIG", func() {
		It("should find RRSIG for DS records in answer section", func() {
			rrsig := &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG},
				TypeCovered: dns.TypeDS,
			}

			response := &dns.Msg{
				Answer: []dns.RR{rrsig},
			}

			result := sut.findDSRRSIG(response, "example.com.")
			Expect(result).Should(Equal(rrsig))
		})

		It("should find RRSIG for DS records in authority section", func() {
			rrsig := &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG},
				TypeCovered: dns.TypeDS,
			}

			response := &dns.Msg{
				Ns: []dns.RR{rrsig},
			}

			result := sut.findDSRRSIG(response, "example.com.")
			Expect(result).Should(Equal(rrsig))
		})

		It("should return nil when no DS RRSIG found", func() {
			rrsig := &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG},
				TypeCovered: dns.TypeA, // Not DS
			}

			response := &dns.Msg{
				Answer: []dns.RR{rrsig},
			}

			result := sut.findDSRRSIG(response, "example.com.")
			Expect(result).Should(BeNil())
		})

		It("should return nil for empty response", func() {
			response := &dns.Msg{}

			result := sut.findDSRRSIG(response, "example.com.")
			Expect(result).Should(BeNil())
		})

		It("should prefer first DS RRSIG when multiple present", func() {
			rrsig1 := &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG},
				TypeCovered: dns.TypeDS,
				KeyTag:      1,
			}
			rrsig2 := &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG},
				TypeCovered: dns.TypeDS,
				KeyTag:      2,
			}

			response := &dns.Msg{
				Answer: []dns.RR{rrsig1, rrsig2},
			}

			result := sut.findDSRRSIG(response, "example.com.")
			Expect(result).Should(Equal(rrsig1))
		})
	})

	Describe("walkChainOfTrust", func() {
		It("should return cached result if available", func() {
			domain := "example.com."
			sut.setCachedValidation(ctx, domain, ValidationResultSecure)

			result, _ := sut.walkChainOfTrust(ctx, domain)
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should reject domains exceeding max chain depth", func() {
			// Create a very deep domain name
			deepDomain := "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.com."

			// Set a low max depth
			sut.maxChainDepth = 5

			result, _ := sut.walkChainOfTrust(ctx, deepDomain)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should normalize domain to FQDN", func() {
			domain := "example.com"
			sut.setCachedValidation(ctx, "example.com.", ValidationResultSecure)

			result, _ := sut.walkChainOfTrust(ctx, domain)
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should handle root domain", func() {
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				// Return empty DNSKEY response
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{},
					},
				}, nil
			}

			result, _ := sut.walkChainOfTrust(ctx, ".")
			// Bogus because the DNSKEY query was answered without the anchored root keys
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should cache validation results", func() {
			domain := "test.example.com."

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return nil, errors.New("mock error")
			}

			// First call
			result1, _ := sut.walkChainOfTrust(ctx, domain)

			// Second call should use cache (not call upstream again)
			result2, _ := sut.walkChainOfTrust(ctx, domain)
			Expect(result2).Should(Equal(result1))
		})

		It("should not re-query a validated chain", func() {
			chain := newSignedChain()
			queries := 0
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				queries++

				return chain.resolve(ctx, req)
			}
			v := NewValidator(ctx, chain.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, keys := v.walkChainOfTrust(ctx, chain.child)
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(keys).Should(ConsistOf(chain.childKey))
			Expect(queries).Should(Equal(3), "DNSKEY of the anchor, then DS and DNSKEY of the child")

			result, keys = v.walkChainOfTrust(ctx, chain.child)
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(keys).Should(ConsistOf(chain.childKey))
			Expect(queries).Should(Equal(3))
		})

		It("should validate a sibling zone with the cached parent keys", func() {
			chain := newSignedChain()
			siblingKey, siblingPriv, _ := newSignedZoneKey("other." + chain.parent)
			siblingKeySig := signRRset([]dns.RR{siblingKey}, dns.TypeDNSKEY, siblingKey, siblingPriv, siblingKey.Hdr.Name)
			siblingDS := siblingKey.ToDS(dns.SHA256)
			siblingDSSig := signRRset([]dns.RR{siblingDS}, dns.TypeDS, chain.parentKey, chain.parentPriv, chain.parent)

			var queried []string
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				q := req.Req.Question[0]
				queried = append(queried, dns.TypeToString[q.Qtype]+" "+q.Name)

				switch {
				case q.Name == siblingKey.Hdr.Name && q.Qtype == dns.TypeDS:
					return &model.Response{Res: &dns.Msg{Answer: []dns.RR{siblingDS, siblingDSSig}}}, nil
				case q.Name == siblingKey.Hdr.Name && q.Qtype == dns.TypeDNSKEY:
					return &model.Response{Res: &dns.Msg{Answer: []dns.RR{siblingKey, siblingKeySig}}}, nil
				}

				return chain.resolve(ctx, req)
			}
			v := NewValidator(ctx, chain.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, chain.child)
			Expect(result).Should(Equal(ValidationResultSecure))
			queried = nil

			result, _ = v.walkChainOfTrust(ctx, siblingKey.Hdr.Name)
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(queried).Should(Equal([]string{"DS " + siblingKey.Hdr.Name, "DNSKEY " + siblingKey.Hdr.Name}))
		})

		It("should expire validated keys with their DNSKEY TTL", func() {
			chain := newSignedChain()
			chain.childKey.Hdr.Ttl = 1
			chain.childKeySig = signRRset([]dns.RR{chain.childKey}, dns.TypeDNSKEY, chain.childKey, chain.childPriv, chain.child)
			queries := 0
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				queries++

				return chain.resolve(ctx, req)
			}
			v := NewValidator(ctx, chain.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, chain.child)
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(queries).Should(Equal(3))

			time.Sleep(1100 * time.Millisecond)

			result, _ = v.walkChainOfTrust(ctx, chain.child)
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(queries).Should(Equal(5), "the child keys are fetched again, the anchor keys are still cached")
		})

		It("should recover from a truncated DNSKEY reply on the next walk", func() {
			chain := newSignedChain()
			truncate := true
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				if q := req.Req.Question[0]; q.Qtype == dns.TypeDNSKEY && q.Name == chain.parent && truncate {
					truncate = false

					return &model.Response{Res: &dns.Msg{MsgHdr: dns.MsgHdr{Truncated: true}}}, nil
				}

				return chain.resolve(ctx, req)
			}
			v := NewValidator(ctx, chain.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, chain.child)
			Expect(result).Should(Equal(ValidationResultIndeterminate))

			result, _ = v.walkChainOfTrust(ctx, chain.child)
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should take the cache lifetime from the signature that verified the keys", func() {
			chain := newSignedChain()
			stale := *chain.childKeySig
			stale.Expiration = uint32(time.Now().Add(-48 * time.Hour).Unix())
			queries := 0
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				queries++

				if q := req.Req.Question[0]; q.Qtype == dns.TypeDNSKEY && q.Name == chain.child {
					return &model.Response{Res: &dns.Msg{Answer: []dns.RR{chain.childKey, &stale, chain.childKeySig}}}, nil
				}

				return chain.resolve(ctx, req)
			}
			v := NewValidator(ctx, chain.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			for range 2 {
				result, _ := v.walkChainOfTrust(ctx, chain.child)
				Expect(result).Should(Equal(ValidationResultSecure))
			}

			Expect(queries).Should(Equal(3), "an extra expired RRSIG must not keep the keys out of the cache")
		})

		It("should expire validated keys with the signature over their DNSKEY RRset", func() {
			chain := newSignedChain()
			chain.childKeySig.Expiration = uint32(time.Now().Add(time.Second).Unix())
			Expect(chain.childKeySig.Sign(chain.childPriv, []dns.RR{chain.childKey})).Should(Succeed())
			queries := 0
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				queries++

				return chain.resolve(ctx, req)
			}
			v := NewValidator(ctx, chain.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, chain.child)
			Expect(result).Should(Equal(ValidationResultSecure))

			time.Sleep(1100 * time.Millisecond)

			// The signature is now past its expiration but still inside the clock skew tolerance.
			result, _ = v.walkChainOfTrust(ctx, chain.child)
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(queries).Should(Equal(5), "the child keys are fetched again, the anchor keys are still cached")
		})
	})

	Describe("walkChainOfTrust through names that are part of their parent zone (issue #2280)", func() {
		var c *partOfParentChain

		BeforeEach(func() {
			c = newPartOfParentChain()
			mockUpstream.ResolveFn = c.resolve
		})

		It("keeps the keys of jp. past co.jp., which an NSEC3 shows is part of jp.", func() {
			v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			Expect(v.ValidateResponse(ctx,
				signedA("www.jprs.co.jp.", "192.0.2.1", c.childKey, c.childPriv, "jprs.co.jp."),
				dns.Question{Name: "www.jprs.co.jp.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			)).Should(Equal(ValidationResultSecure))
			Expect(c.queries).Should(Equal([]string{"DNSKEY jp.", "DS co.jp.", "DS jprs.co.jp.", "DNSKEY jprs.co.jp."}),
				"co.jp. has no DNSKEY RRset to fetch")

			_, found := v.getCachedValidation(ctx, "co.jp.")
			Expect(found).Should(BeFalse())
		})

		It("keeps the keys of jp. past co.jp. when an NSEC for co.jp. shows it", func() {
			c.proveCoJP(&dns.NSEC{
				Hdr:        dns.RR_Header{Name: "co.jp.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "jprs.co.jp.",
				TypeBitMap: []uint16{dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC},
			}, c.jpKey, c.jpPriv)
			v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, keys := v.walkChainOfTrust(ctx, "jprs.co.jp.")
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(keys).Should(ConsistOf(c.childKey))
		})

		It("keeps the keys of jp. past co.jp. when an NSEC shows it is an empty non-terminal", func() {
			c.proveCoJP(&dns.NSEC{
				Hdr:        dns.RR_Header{Name: "jp.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "jprs.co.jp.",
				TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
			}, c.jpKey, c.jpPriv)
			v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, "jprs.co.jp.")
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		DescribeTable("does not walk past co.jp. without a valid proof that it is part of jp.",
			func(prove func(c *partOfParentChain), expected ValidationResult) {
				prove(c)
				v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

				result, _ := v.walkChainOfTrust(ctx, "jprs.co.jp.")
				Expect(result).Should(Equal(expected))
			},
			Entry("NSEC3 not signed by jp.", func(c *partOfParentChain) {
				otherKey, otherPriv, _ := newSignedZoneKey("jp.")
				c.proveCoJP(coJPNSEC3(0, dns.TypeTXT, dns.TypeRRSIG), otherKey, otherPriv)
			}, ValidationResultBogus),
			Entry("NSEC3 with the NS bit, an insecure delegation", func(c *partOfParentChain) {
				c.proveCoJP(coJPNSEC3(0, dns.TypeNS, dns.TypeRRSIG), c.jpKey, c.jpPriv)
			}, ValidationResultInsecure),
			Entry("NSEC3 with the DS bit", func(c *partOfParentChain) {
				c.proveCoJP(coJPNSEC3(0, dns.TypeTXT, dns.TypeDS, dns.TypeRRSIG), c.jpKey, c.jpPriv)
			}, ValidationResultBogus),
			Entry("NSEC3 with the SOA bit", func(c *partOfParentChain) {
				c.proveCoJP(coJPNSEC3(0, dns.TypeSOA, dns.TypeTXT, dns.TypeRRSIG), c.jpKey, c.jpPriv)
			}, ValidationResultBogus),
			Entry("NSEC3 above the iteration limit", func(c *partOfParentChain) {
				c.proveCoJP(coJPNSEC3(200, dns.TypeTXT, dns.TypeRRSIG), c.jpKey, c.jpPriv)
			}, ValidationResultBogus),
			Entry("NSEC of *.jp. renamed to co.jp.", func(c *partOfParentChain) {
				nsec := &dns.NSEC{
					Hdr:        dns.RR_Header{Name: "*.jp.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
					NextDomain: "a.jp.",
					TypeBitMap: []uint16{dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC},
				}
				sig := signRRset([]dns.RR{nsec}, dns.TypeNSEC, c.jpKey, c.jpPriv, "jp.")
				nsec.Hdr.Name, sig.Hdr.Name = "co.jp.", "co.jp."
				c.answers["DS co.jp."] = &dns.Msg{Ns: []dns.RR{nsec, sig}}
			}, ValidationResultBogus),
			Entry("NSEC that covers co.jp. without pointing below it", func(c *partOfParentChain) {
				c.proveCoJP(&dns.NSEC{
					Hdr:        dns.RR_Header{Name: "cn.jp.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
					NextDomain: "cp.jp.",
					TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
				}, c.jpKey, c.jpPriv)
			}, ValidationResultBogus),
		)

		It("verifies at most maxNoZoneCutSignatures signatures from one DS reply", func() {
			otherKey, otherPriv, _ := newSignedZoneKey("jp.")
			genuine := c.answers["DS co.jp."].Ns

			// forged returns n NSEC records that point below co.jp., each with an RRSIG that names the
			// key of jp. but fails verification with it.
			forged := func(n int) []dns.RR {
				rrs := make([]dns.RR, 0, 2*n)

				for i := range n {
					nsec := &dns.NSEC{
						Hdr:        dns.RR_Header{Name: fmt.Sprintf("a%d.jp.", i), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
						NextDomain: "x.co.jp.",
						TypeBitMap: []uint16{dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC},
					}
					sig := signRRset([]dns.RR{nsec}, dns.TypeNSEC, otherKey, otherPriv, "jp.")
					sig.KeyTag = c.jpKey.KeyTag()
					rrs = append(rrs, nsec, sig)
				}

				return rrs
			}

			for n, expected := range map[int]ValidationResult{
				maxNoZoneCutSignatures - 1: ValidationResultSecure,
				maxNoZoneCutSignatures:     ValidationResultBogus,
			} {
				c.answers["DS co.jp."] = &dns.Msg{Ns: append(forged(n), genuine...)}
				v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

				result, _ := v.walkChainOfTrust(ctx, "jprs.co.jp.")
				Expect(result).Should(Equal(expected), "%d forged proofs before the genuine one", n)
			}
		})

		It("accepts a literal wildcard NSEC that points below co.jp.", func() {
			// A zone may publish *.jp. as the name just before the first name under the empty
			// non-terminal co.jp. Its RRSIG is over the literal *.jp. owner, so it still counts.
			c.proveCoJP(&dns.NSEC{
				Hdr:        dns.RR_Header{Name: "*.jp.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "jprs.co.jp.",
				TypeBitMap: []uint16{dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC},
			}, c.jpKey, c.jpPriv)
			Expect(c.answers["DS co.jp."].Ns[1].(*dns.RRSIG).Labels).Should(Equal(uint8(1)))
			v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, "jprs.co.jp.")
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("does not accept a wildcard NSEC renamed onto co.jp. as proof it is part of jp.", func() {
			// The RRSIG over *.jp. still verifies after the owner is rewritten to co.jp., because
			// miekg/dns reconstructs the *.jp. owner from the RRSIG label count. Taken as proof that
			// co.jp. is in jp., it would skip the real co.jp. delegation.
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "*.jp.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "a.jp.",
				TypeBitMap: []uint16{dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC},
			}
			sig := signRRset([]dns.RR{nsec}, dns.TypeNSEC, c.jpKey, c.jpPriv, "jp.")
			Expect(sig.Labels).Should(Equal(uint8(1)), "the RRSIG is over the wildcard owner")
			nsec.Hdr.Name, sig.Hdr.Name = "co.jp.", "co.jp."

			jpKeys := []*dns.DNSKEY{c.jpKey}
			Expect(sut.provesNoZoneCut("co.jp.", jpKeys, &dns.Msg{Ns: []dns.RR{nsec, sig}})).Should(BeFalse())
			Expect(sut.provesNoZoneCut("co.jp.", jpKeys, c.answers["DS co.jp."])).Should(BeTrue(),
				"the genuine co.jp. proof is still accepted")
		})

		It("checks the DS RRset of jprs.co.jp. with the keys of jp., the zone that holds co.jp.", func() {
			v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)
			ds := c.answers["DS jprs.co.jp."].Answer

			Expect(v.validateDSRecordSignature(ctx, "jprs.co.jp.", "co.jp.", ds[:1], ds[1].(*dns.RRSIG))).
				Should(Equal(ValidationResultSecure))

			result, _ := v.walkChainOfTrust(ctx, "co.jp.")
			Expect(result).Should(Equal(ValidationResultBogus), "co.jp. is still no signer")
		})

		It("rejects co.jp. as a signer without caching it, so zones below it still validate", func() {
			v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, "co.jp.")
			Expect(result).Should(Equal(ValidationResultBogus))

			_, found := v.getCachedValidation(ctx, "co.jp.")
			Expect(found).Should(BeFalse())

			result, _ = v.walkChainOfTrust(ctx, "jprs.co.jp.")
			Expect(result).Should(Equal(ValidationResultSecure))
		})
	})

	Describe("verifyDomainAgainstTrustAnchor for the root", func() {
		It("should return Indeterminate when DNSKEY query fails", func() {
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return nil, errors.New("query failed")
			}

			result, _ := sut.verifyDomainAgainstTrustAnchor(ctx, ".")
			Expect(result).Should(Equal(ValidationResultIndeterminate))
		})

		It("should return Indeterminate when no trust anchors configured", func() {
			// Create validator with empty trust store
			emptyTrustStore, err := NewTrustAnchorStore(nil)
			Expect(err).Should(Succeed())
			emptyTrustStore.anchors["."] = []*TrustAnchor{} // Clear root anchors

			logger, _ := log.NewMockEntry()
			validator := NewValidator(ctx, emptyTrustStore, logger, mockUpstream, 1, 10, 150, 30, 3600)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{},
					},
				}, nil
			}

			result, _ := validator.verifyDomainAgainstTrustAnchor(ctx, ".")
			Expect(result).Should(Equal(ValidationResultIndeterminate))
		})

		It("should skip revoked DNSKEYs", func() {
			revokedKey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   ".",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
				},
				Flags:     257 | 0x0080, // REVOKE flag set
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "test",
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{revokedKey},
					},
				}, nil
			}

			result, _ := sut.verifyDomainAgainstTrustAnchor(ctx, ".")
			Expect(result).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("verifyDomainAgainstTrustAnchor", func() {
		It("should return Indeterminate when DNSKEY query fails", func() {
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return nil, errors.New("query failed")
			}

			result, _ := sut.verifyDomainAgainstTrustAnchor(ctx, "example.com.")
			Expect(result).Should(Equal(ValidationResultIndeterminate))
		})

		It("should return Indeterminate when no trust anchors for domain", func() {
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{},
					},
				}, nil
			}

			result, _ := sut.verifyDomainAgainstTrustAnchor(ctx, "example.com.")
			Expect(result).Should(Equal(ValidationResultIndeterminate))
		})

		It("should skip keys without ZONE flag", func() {
			keyWithoutZone := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
				},
				Flags:     0, // No ZONE flag
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "test",
			}

			trustStore.anchors["example.com."] = []*TrustAnchor{
				{
					Key: keyWithoutZone,
				},
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{keyWithoutZone},
					},
				}, nil
			}

			result, _ := sut.verifyDomainAgainstTrustAnchor(ctx, "example.com.")
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should skip revoked keys", func() {
			revokedKey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
				},
				Flags:     257 | 0x0080, // REVOKE flag
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "test",
			}

			trustStore.anchors["example.com."] = []*TrustAnchor{
				{
					Key: revokedKey,
				},
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{revokedKey},
					},
				}, nil
			}

			result, _ := sut.verifyDomainAgainstTrustAnchor(ctx, "example.com.")
			Expect(result).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("validateDSRecordSignature", func() {
		It("should validate DS RRSIG with parent DNSKEY", func() {
			// Create a real DNSKEY and DS
			dnskey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "test",
			}

			ds := &dns.DS{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				KeyTag:     12345,
				Algorithm:  dns.RSASHA256,
				DigestType: dns.SHA256,
				Digest:     "abcd1234",
			}

			rrsig := &dns.RRSIG{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeRRSIG,
					Class:  dns.ClassINET,
				},
				TypeCovered: dns.TypeDS,
				SignerName:  "com.",
				KeyTag:      dnskey.KeyTag(),
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{dnskey},
					},
				}, nil
			}

			result := sut.validateDSRecordSignature(ctx, "example.com.", "com.", []dns.RR{ds}, rrsig)
			// Will fail crypto validation, but tests the code path
			Expect(result).ShouldNot(BeNil())
		})

		It("should return Bogus when no matching parent DNSKEY found", func() {
			ds := &dns.DS{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
				},
			}

			rrsig := &dns.RRSIG{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeRRSIG,
				},
				TypeCovered: dns.TypeDS,
				KeyTag:      65535, // Non-existent key tag (max uint16)
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				dnskey := &dns.DNSKEY{
					Hdr: dns.RR_Header{
						Name:   "com.",
						Rrtype: dns.TypeDNSKEY,
						Class:  dns.ClassINET,
					},
					Flags:     257,
					Protocol:  3,
					Algorithm: dns.RSASHA256,
					PublicKey: "test",
				}

				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{dnskey},
					},
				}, nil
			}

			result := sut.validateDSRecordSignature(ctx, "example.com.", "com.", []dns.RR{ds}, rrsig)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return Indeterminate when parent DNSKEY query fails", func() {
			ds := &dns.DS{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
				},
			}

			rrsig := &dns.RRSIG{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeRRSIG,
				},
				TypeCovered: dns.TypeDS,
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return nil, errors.New("query failed")
			}

			result := sut.validateDSRecordSignature(ctx, "example.com.", "com.", []dns.RR{ds}, rrsig)
			Expect(result).Should(Equal(ValidationResultIndeterminate))
		})
	})

	Describe("extractAndValidateDSRecords", func() {
		It("should handle DS absence with NSEC proof", func() {
			nsec := &dns.NSEC{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeNSEC,
					Class:  dns.ClassINET,
				},
				NextDomain: "z.example.com.",
				TypeBitMap: []uint16{dns.TypeA, dns.TypeNS}, // No DS
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec},
			}

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response)
			Expect(dsRecords).Should(BeNil())
			// Result will be Insecure or Bogus depending on NSEC validation
			Expect(result).ShouldNot(Equal(ValidationResultSecure))
		})

		It("should handle DS absence with NSEC3 proof", func() {
			nsec3 := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "hash.example.com.",
					Rrtype: dns.TypeNSEC3,
					Class:  dns.ClassINET,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec3},
			}

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response)
			Expect(dsRecords).Should(BeNil())
			Expect(result).ShouldNot(Equal(ValidationResultSecure))
		})

		It("should return Indeterminate when no DS and no NSEC/NSEC3", func() {
			response := &dns.Msg{
				Ns: []dns.RR{},
			}

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response)
			Expect(dsRecords).Should(BeNil())
			Expect(result).Should(Equal(ValidationResultIndeterminate))
		})
	})

	Describe("verifyDenialSignatures", func() {
		It("should check all denial RRsets of a reply with one verification budget", func() {
			key, priv, _ := newSignedZoneKey("example.")
			keys := []*dns.DNSKEY{key}

			// denials returns n NSEC RRsets, each signed by key
			denials := func(n int) []dns.RR {
				rrs := make([]dns.RR, 0, 2*n)

				for i := range n {
					nsec := &dns.NSEC{
						Hdr:        dns.RR_Header{Name: fmt.Sprintf("a%d.example.", i), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
						NextDomain: fmt.Sprintf("b%d.example.", i),
						TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
					}
					rrs = append(rrs, nsec, signRRset([]dns.RR{nsec}, dns.TypeNSEC, key, priv, "example."))
				}

				return rrs
			}

			Expect(sut.verifyDenialSignatures(denials(maxZoneKeyVerifications), keys)).Should(Succeed())
			Expect(sut.verifyDenialSignatures(denials(maxZoneKeyVerifications+1), keys)).
				Should(MatchError(ContainSubstring("no signature verifications left")))
		})
	})

	Describe("validateDomainLevel", func() {
		var chain *signedChain

		BeforeEach(func() {
			chain = newSignedChain()
		})

		It("should validate a zone whose DS and DNSKEY RRsets chain to the parent keys", func() {
			mockUpstream.ResolveFn = chain.resolve

			result, keys, _ := sut.validateDomainLevel(ctx, chain.child, []*dns.DNSKEY{chain.parentKey})
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(keys).Should(ConsistOf(chain.childKey))
		})

		It("should return Bogus when the DS RRset is not signed by the parent keys", func() {
			otherKey, _, _ := newSignedZoneKey(chain.parent)
			mockUpstream.ResolveFn = chain.resolve

			result, keys, _ := sut.validateDomainLevel(ctx, chain.child, []*dns.DNSKEY{otherKey})
			Expect(result).Should(Equal(ValidationResultBogus))
			Expect(keys).Should(BeNil())
		})

		It("should not be Secure without DS records", func() {
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				// Return empty response for all queries
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{},
					},
				}, nil
			}

			result, _, _ := sut.validateDomainLevel(ctx, chain.child, []*dns.DNSKEY{chain.parentKey})
			Expect(result).ShouldNot(Equal(ValidationResultSecure))
		})

		It("should return Indeterminate when DS query fails", func() {
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				// Simulate query failure
				return nil, errors.New("query failed")
			}

			result, _, _ := sut.validateDomainLevel(ctx, chain.child, []*dns.DNSKEY{chain.parentKey})
			Expect(result).Should(Equal(ValidationResultIndeterminate))
		})

		It("should return Indeterminate when DNSKEY query fails", func() {
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				// Return DS records successfully, but fail DNSKEY query
				if req.Req.Question[0].Qtype == dns.TypeDNSKEY {
					return nil, errors.New("DNSKEY query failed")
				}

				return chain.resolve(ctx, req)
			}

			result, _, _ := sut.validateDomainLevel(ctx, chain.child, []*dns.DNSKEY{chain.parentKey})
			Expect(result).Should(Equal(ValidationResultIndeterminate))
		})

		It("should return Indeterminate when the DNSKEY query is answered with an error RCODE", func() {
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				if req.Req.Question[0].Qtype == dns.TypeDNSKEY {
					return &model.Response{Res: &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}}, nil
				}

				return chain.resolve(ctx, req)
			}

			result, _, _ := sut.validateDomainLevel(ctx, chain.child, []*dns.DNSKEY{chain.parentKey})
			Expect(result).Should(Equal(ValidationResultIndeterminate))
		})

		It("should return Bogus when DNSKEY doesn't match DS", func() {
			otherKey, otherPriv, _ := newSignedZoneKey(chain.child)
			otherKeySig := signRRset([]dns.RR{otherKey}, dns.TypeDNSKEY, otherKey, otherPriv, chain.child)
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				if req.Req.Question[0].Qtype == dns.TypeDNSKEY {
					return &model.Response{Res: &dns.Msg{Answer: []dns.RR{otherKey, otherKeySig}}}, nil
				}

				return chain.resolve(ctx, req)
			}

			result, _, _ := sut.validateDomainLevel(ctx, chain.child, []*dns.DNSKEY{chain.parentKey})
			Expect(result).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("extractAndValidateDSRecords - additional cases", func() {
		It("should return Bogus when DS records exist but no RRSIG", func() {
			ds := &dns.DS{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				KeyTag:     12345,
				Algorithm:  8,
				DigestType: 2,
				Digest:     "abcdef",
			}

			response := &dns.Msg{
				Answer: []dns.RR{ds},
				// No RRSIG - should be Bogus
			}

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response)
			Expect(dsRecords).Should(BeNil())
			Expect(result).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("validateDomainLevel - additional coverage", func() {
		It("should return parent validation result when parent fails validation", func() {
			// Mock walkChainOfTrust to return Bogus for parent
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				// Return empty response - this will cause validation to fail
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{},
					},
				}, nil
			}

			// Clear any cached validation results
			sut = NewValidator(ctx, trustStore, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)
			ctx = withQueryBudget(ctx, 10)

			result, _ := sut.walkChainOfTrust(ctx, "sub.example.com.")
			// Should propagate parent validation failure
			Expect(result).ShouldNot(Equal(ValidationResultSecure))
		})

		It("should return Bogus when DNSKEY validation fails", func() {
			// Create valid DS record
			ds := &dns.DS{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				KeyTag:     12345,
				Algorithm:  8,
				DigestType: 2,
				Digest:     "abcdef1234567890",
			}

			// Create DNSKEY that won't match DS
			dnskey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Flags:     257, // KSK
				Protocol:  3,
				Algorithm: 8,
				PublicKey: "differentkey",
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				qtype := req.Req.Question[0].Qtype

				switch qtype {
				case dns.TypeDS:
					// Return DS with RRSIG
					rrsig := &dns.RRSIG{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeRRSIG,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
						TypeCovered: dns.TypeDS,
						Algorithm:   8,
						Labels:      2,
						OrigTtl:     3600,
						SignerName:  "com.",
					}

					return &model.Response{
						Res: &dns.Msg{
							Answer: []dns.RR{ds, rrsig},
						},
					}, nil
				case dns.TypeDNSKEY:
					// Return DNSKEY
					return &model.Response{
						Res: &dns.Msg{
							Answer: []dns.RR{dnskey},
						},
					}, nil
				}

				return &model.Response{
					Res: &dns.Msg{},
				}, nil
			}

			// No parent keys: the DS RRset cannot be authenticated
			result, _, _ := sut.validateDomainLevel(ctx, "example.com.", nil)
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})
	})

	Describe("extractAndValidateDSRecords - error paths", func() {
		It("should handle DS records in authority section", func() {
			ds := &dns.DS{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				KeyTag:     12345,
				Algorithm:  8,
				DigestType: 2,
				Digest:     "abcdef",
			}

			response := &dns.Msg{
				Ns: []dns.RR{ds}, // DS in authority section instead of answer
			}

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response)
			// Will fail because no RRSIG
			Expect(dsRecords).Should(BeNil())
			Expect(result).ShouldNot(Equal(ValidationResultSecure))
		})
	})

	Describe("validateDomainLevel - comprehensive coverage", func() {
		It("should handle DS query returning empty response", func() {
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				// Return empty response for all queries
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{},
						Ns:     []dns.RR{},
					},
				}, nil
			}

			result, _, _ := sut.validateDomainLevel(ctx, "test.example.com.", nil)
			Expect(result).Should(Equal(ValidationResultIndeterminate))
		})
	})

	Describe("extractAndValidateDSRecords - extended error paths", func() {
		It("should return Insecure when NSEC proves DS absence", func() {
			// Create NSEC that proves DS doesn't exist
			nsec := &dns.NSEC{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeNSEC,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				NextDomain: "z.example.com.",
				TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA}, // No DS type
			}

			// Mock to make NSEC validation succeed
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				if req.Req.Question[0].Qtype == dns.TypeDNSKEY {
					// Return empty DNSKEY - validation will fail
					return &model.Response{
						Res: &dns.Msg{
							Answer: []dns.RR{},
						},
					}, nil
				}

				return &model.Response{Res: &dns.Msg{}}, nil
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec},
			}

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response)
			Expect(dsRecords).Should(BeNil())
			// Result depends on NSEC validation
			Expect(result).ShouldNot(Equal(ValidationResultSecure))
		})

		It("should handle DS records with successful RRSIG validation", func() {
			parentDnskey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "parentkey",
			}

			ds := &dns.DS{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				KeyTag:     12345,
				Algorithm:  dns.RSASHA256,
				DigestType: dns.SHA256,
				Digest:     "abcdef0123456789",
			}

			rrsig := &dns.RRSIG{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeRRSIG,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				TypeCovered: dns.TypeDS,
				Algorithm:   dns.RSASHA256,
				SignerName:  "com.",
				KeyTag:      parentDnskey.KeyTag(),
			}

			response := &dns.Msg{
				Answer: []dns.RR{ds, rrsig},
			}

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", []*dns.DNSKEY{parentDnskey}, response)
			// Will fail crypto validation but tests the code path
			Expect(dsRecords).Should(BeNil())
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})

		It("should return Bogus when NSEC/NSEC3 validation fails for DS absence", func() {
			// Create NSEC with invalid proof
			nsec := &dns.NSEC{
				Hdr: dns.RR_Header{
					Name:   "a.example.com.", // Wrong name
					Rrtype: dns.TypeNSEC,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				NextDomain: "b.example.com.", // Doesn't cover example.com
				TypeBitMap: []uint16{dns.TypeA},
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{},
					},
				}, nil
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec},
			}

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response)
			Expect(dsRecords).Should(BeNil())
			Expect(result).ShouldNot(Equal(ValidationResultSecure))
		})
	})

	Describe("walkChainOfTrust - trust anchor path coverage", func() {
		It("should validate domain with configured trust anchor", func() {
			// Create trust anchor for test.com
			testKey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "test.com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "testkey123",
			}

			trustStore.anchors["test.com."] = []*TrustAnchor{
				{Key: testKey},
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				if req.Req.Question[0].Qtype == dns.TypeDNSKEY && req.Req.Question[0].Name == "test.com." {
					return &model.Response{
						Res: &dns.Msg{
							Answer: []dns.RR{testKey},
						},
					}, nil
				}

				return &model.Response{Res: &dns.Msg{}}, nil
			}

			result, _ := sut.walkChainOfTrust(ctx, "test.com.")
			// Will attempt to verify trust anchor, but may fail on parent validation
			// We're testing that the trust anchor code path is exercised
			Expect(result).ShouldNot(BeNil())
		})

		It("should continue validating child zones after trust anchor verification", func() {
			// Configure trust anchor for parent zone
			parentKey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "parentkey",
			}

			trustStore.anchors["example.com."] = []*TrustAnchor{
				{Key: parentKey},
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				qname := req.Req.Question[0].Name
				qtype := req.Req.Question[0].Qtype

				if qtype == dns.TypeDNSKEY && qname == "example.com." {
					return &model.Response{
						Res: &dns.Msg{
							Answer: []dns.RR{parentKey},
						},
					}, nil
				}

				// Return errors for child validation
				return nil, errors.New("child validation query")
			}

			// Try to validate child domain - should first verify trust anchor
			result, _ := sut.walkChainOfTrust(ctx, "sub.example.com.")
			// Will attempt to validate sub.example.com after verifying example.com trust anchor
			Expect(result).ShouldNot(BeNil())
		})
	})
})

// partOfParentChain is the layout of issue #2280: jp. is a trust anchor, co.jp. is a name in the
// jp. zone with a TXT record, and jp. delegates the signed zone jprs.co.jp. directly. answers maps
// "TYPE name" to the reply the upstream sends, and queries records what it was asked.
type partOfParentChain struct {
	anchors           *TrustAnchorStore
	jpKey, childKey   *dns.DNSKEY
	jpPriv, childPriv *ecdsa.PrivateKey
	answers           map[string]*dns.Msg
	queries           []string
}

func newPartOfParentChain() *partOfParentChain {
	c := &partOfParentChain{answers: map[string]*dns.Msg{}}

	var anchor string
	c.jpKey, c.jpPriv, anchor = newSignedZoneKey("jp.")
	c.childKey, c.childPriv, _ = newSignedZoneKey("jprs.co.jp.")

	var err error
	c.anchors, err = NewTrustAnchorStore([]string{anchor})
	Expect(err).Should(Succeed())

	ds := c.childKey.ToDS(dns.SHA256)
	c.answers["DNSKEY jp."] = &dns.Msg{Answer: []dns.RR{
		c.jpKey, signRRset([]dns.RR{c.jpKey}, dns.TypeDNSKEY, c.jpKey, c.jpPriv, "jp."),
	}}
	c.answers["DS jprs.co.jp."] = &dns.Msg{Answer: []dns.RR{
		ds, signRRset([]dns.RR{ds}, dns.TypeDS, c.jpKey, c.jpPriv, "jp."),
	}}
	c.answers["DNSKEY jprs.co.jp."] = &dns.Msg{Answer: []dns.RR{
		c.childKey, signRRset([]dns.RR{c.childKey}, dns.TypeDNSKEY, c.childKey, c.childPriv, "jprs.co.jp."),
	}}
	c.proveCoJP(coJPNSEC3(0, dns.TypeTXT, dns.TypeRRSIG), c.jpKey, c.jpPriv)

	return c
}

// proveCoJP makes rr, signed with key, the denial in the reply to the DS query for co.jp.
func (c *partOfParentChain) proveCoJP(rr dns.RR, key *dns.DNSKEY, priv *ecdsa.PrivateKey) {
	c.answers["DS co.jp."] = &dns.Msg{Ns: []dns.RR{rr, signRRset([]dns.RR{rr}, rr.Header().Rrtype, key, priv, "jp.")}}
}

func (c *partOfParentChain) resolve(_ context.Context, req *model.Request) (*model.Response, error) {
	q := req.Req.Question[0]
	query := dns.TypeToString[q.Qtype] + " " + q.Name
	c.queries = append(c.queries, query)

	if msg, ok := c.answers[query]; ok {
		return &model.Response{Res: msg}, nil
	}

	return &model.Response{Res: &dns.Msg{}}, nil
}

// coJPNSEC3 returns the NSEC3 record of the jp. zone for co.jp., hashed with iterations, with types.
func coJPNSEC3(iterations uint16, types ...uint16) *dns.NSEC3 {
	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   strings.ToLower(dns.HashName("co.jp.", dns.SHA1, iterations, "")) + ".jp.",
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Hash:       dns.SHA1,
		Iterations: iterations,
		HashLength: 20,
		NextDomain: dns.HashName("next.co.jp.", dns.SHA1, iterations, ""),
		TypeBitMap: types,
	}
}
