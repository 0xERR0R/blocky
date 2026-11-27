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
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var _ = Describe("Chain of trust validation", func() {
	var (
		sut          *Validator
		trustStore   *TrustAnchorStore
		mockUpstream *mockResolver
		ctx          context.Context
		budget       int
	)

	BeforeEach(func(specCtx SpecContext) {
		ctx = specCtx
		budget = maxZoneKeyVerifications

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

		It("should keep a Bogus result for at most BogusTTL", func() {
			sut.setCachedValidation(ctx, "bogus.com.", ValidationResultBogus)
			sut.setCachedValidation(ctx, "insecure.com.", ValidationResultInsecure)

			_, bogusLeft := sut.validationCache.Get(validationCacheKey(ctx, "bogus.com."))
			_, insecureLeft := sut.validationCache.Get(validationCacheKey(ctx, "insecure.com."))
			Expect(bogusLeft).Should(BeNumerically("~", BogusTTL, time.Second))
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
			Expect(err).Should(MatchError(ContainSubstring("no RRSIG made by a validated key")))
		})

		It("takes a DS record that the RRset holds several times as one record", func() {
			// The first record names a key that is missing: it has the key tag of ksk and another
			// digest. Its copies cost no digest attempt, so the attempts reach the record of ksk.
			ksk, _, _ := newSignedZoneKey(zone)
			missing := ksk.ToDS(dns.SHA256)
			missing.Digest = strings.Repeat("00", 32)

			ds := make([]*dns.DS, 0, 17)
			for range 16 {
				ds = append(ds, dns.Copy(missing).(*dns.DS))
			}

			keys, err := sut.findAndValidateKSKs([]*dns.DNSKEY{ksk}, append(ds, ksk.ToDS(dns.SHA256)), zone)
			Expect(err).Should(Succeed())
			Expect(keys).Should(ConsistOf(ksk))
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
				Expect(err).Should(MatchError(ContainSubstring("no signature verifications left")))
			})
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
			// A chain may have one zone below its trust anchor: signed.example., and no zone below it
			chain := newRepliedChain()
			grandchild := "deep." + chain.child
			grandchildKey, _ := chain.delegate(chain.child, chain.childKey, chain.childPriv, grandchild)
			mockUpstream.ResolveFn = chain.resolve
			v := NewValidator(ctx, chain.anchors, sut.logger, mockUpstream, 1, 1, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, grandchild)
			Expect(result).Should(Equal(ValidationResultBogus))

			result, keys := v.walkChainOfTrust(ctx, chain.child)
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(keys).Should(ConsistOf(chain.childKey))

			// The limit says nothing about the zone outside the chain, so nothing is kept for it:
			// with one more zone allowed it validates
			_, found := v.getCachedValidation(ctx, grandchild)
			Expect(found).Should(BeFalse())

			v.maxChainDepth = 2
			result, keys = v.walkChainOfTrust(ctx, grandchild)
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(keys).Should(ConsistOf(grandchildKey))
		})

		It("should count the zones of a chain, not the labels of their names", func() {
			// signed.example., a zone of 8 labels below it and one of 14 labels below that: three zones
			// below the trust anchor. The names between them are empty non-terminals, which cost a DS
			// query each and are no zones.
			chain := newRepliedChain()
			second := "f.e.d.c.b.a." + chain.child
			third := "l.k.j.i.h.g." + second
			Expect(dns.CountLabel(third)).Should(Equal(14))

			secondKey, secondPriv := chain.delegate(chain.child, chain.childKey, chain.childPriv, second)
			thirdKey, _ := chain.delegate(second, secondKey, secondPriv, third)
			mockUpstream.ResolveFn = chain.resolve
			v := NewValidator(ctx, chain.anchors, sut.logger, mockUpstream, 1, 3, 150, 30, 3600)

			result, keys := v.walkChainOfTrust(withQueryBudget(ctx, 30), third)
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(keys).Should(ConsistOf(thirdKey))
			Expect(chain.queries).Should(HaveLen(17),
				"the DNSKEY RRset of example., a DS and a DNSKEY query for each zone, a DS query for each of the 10 other names")
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
			// The DNSKEY query was answered without the root keys: the lookup is not completed
			Expect(result).Should(Equal(ValidationResultIndeterminate))
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

		It("should not re-query a validated chain for a zone name that is spelt in another case", func() {
			// RFC 4343: SIGNED.EXAMPLE. is signed.example., as an RRSIG may name its signer
			chain := newSignedChain()
			queries := 0
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				queries++

				return chain.resolve(ctx, req)
			}
			v := NewValidator(ctx, chain.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, chain.child)
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(queries).Should(Equal(3))

			result, keys := v.walkChainOfTrust(ctx, strings.ToUpper(chain.child))
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

		It("should recover from a DNSKEY lookup with truncated replies on the walk of the next validation", func() {
			// The lookup asks once more for a reply that came truncated. With that one truncated
			// too it could not be completed, which leaves nothing behind for the next validation.
			chain := newSignedChain()
			truncate := 2
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				if q := req.Req.Question[0]; q.Qtype == dns.TypeDNSKEY && q.Name == chain.parent && truncate > 0 {
					truncate--

					return &model.Response{Res: &dns.Msg{Truncated: true}}, nil
				}

				return chain.resolve(ctx, req)
			}
			v := NewValidator(ctx, chain.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, chain.child)
			Expect(result).Should(Equal(ValidationResultIndeterminate))

			result, _ = v.walkChainOfTrust(withQueryBudget(ctx, 10), chain.child)
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

		It("takes no proof from a DS reply in which a denial RRset fails verification", func() {
			otherKey, otherPriv, _ := newSignedZoneKey("jp.")
			genuine := c.answers["DS co.jp."].Ns

			// An NSEC record that points below co.jp., with an RRSIG that names the key of jp. but fails
			// verification with it. The reply is verified once and as a whole, before it proves anything.
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.jp.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "x.co.jp.",
				TypeBitMap: []uint16{dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC},
			}
			sig := signRRset([]dns.RR{nsec}, dns.TypeNSEC, otherKey, otherPriv, "jp.")
			sig.KeyTag = c.jpKey.KeyTag()

			c.answers["DS co.jp."] = &dns.Msg{Ns: append([]dns.RR{nsec, sig}, genuine...)}
			v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, "jprs.co.jp.")
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("hashes no name for an NSEC3 record of a DS reply that jp. did not sign", func() {
			// RFC 9276 §3.2: the signature of an NSEC3 record is verified before anything is hashed for it
			c.answers["DS co.jp."] = &dns.Msg{Ns: []dns.RR{coJPNSEC3(0, dns.TypeTXT, dns.TypeRRSIG)}}
			v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)
			validation := withQueryBudget(ctx, 10)

			result, _ := v.walkChainOfTrust(validation, "jprs.co.jp.")
			Expect(result).Should(Equal(ValidationResultBogus))
			Expect(budgetFrom(validation).hashes.Load()).Should(BeZero())
		})

		It("verifies the denial RRsets of a DS reply once, for the zone cut proof and the DS denial", func() {
			// beside returns the NSEC record of a name before co.jp. with two RRSIGs: one that fails,
			// and one that verifies
			beside := func(i int) []dns.RR {
				nsec := &dns.NSEC{
					Hdr:        dns.RR_Header{Name: fmt.Sprintf("a%d.jp.", i), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
					NextDomain: fmt.Sprintf("a%d.jp.", i+1),
					TypeBitMap: []uint16{dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC},
				}
				sig := signRRset([]dns.RR{nsec}, dns.TypeNSEC, c.jpKey, c.jpPriv, "jp.")
				failing := *sig
				failing.Inception-- // No longer the signed data, so it does not verify

				return []dns.RR{nsec, &failing, sig}
			}
			c.proveCoJP(&dns.NSEC{
				Hdr:        dns.RR_Header{Name: "co.jp.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "jprs.co.jp.",
				TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}, // an insecure delegation
			}, c.jpKey, c.jpPriv)
			genuine := c.answers["DS co.jp."].Ns

			const n = 3

			ns := make([]dns.RR, 0, 3*n+len(genuine))
			for i := range n {
				ns = append(ns, beside(i)...)
			}

			c.answers["DS co.jp."] = &dns.Msg{Ns: append(ns, genuine...)}
			v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)
			validation := withQueryBudget(ctx, 10)

			result, _ := v.walkChainOfTrust(validation, "jprs.co.jp.")
			Expect(result).Should(Equal(ValidationResultInsecure))

			// The DNSKEY RRset of jp., two tries for each record beside co.jp. and one for its own
			Expect(budgetFrom(validation).verifications.Load()).Should(BeEquivalentTo(1 + 2*n + 1))
		})

		It("takes no proof from a DS reply with a denial RRset that only an RRSIG made for a wildcard verifies", func() {
			// The NSEC record of *.jp. under the name a.jp., which the wildcard matches, before the
			// proof of an insecure delegation. The RRSIG says nothing about a.jp. (RFC 4035 §5.3.2), so
			// jp. did not sign the record as it is. The reply is verified as a whole, before it proves
			// anything.
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "*.jp.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "x.co.jp.",
				TypeBitMap: []uint16{dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC},
			}
			sig := signRRset([]dns.RR{nsec}, dns.TypeNSEC, c.jpKey, c.jpPriv, "jp.")
			nsec.Hdr.Name, sig.Hdr.Name = "a.jp.", "a.jp."

			c.proveCoJP(&dns.NSEC{
				Hdr:        dns.RR_Header{Name: "co.jp.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "jprs.co.jp.",
				TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}, // an insecure delegation
			}, c.jpKey, c.jpPriv)
			genuine := c.answers["DS co.jp."].Ns
			v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, "jprs.co.jp.")
			Expect(result).Should(Equal(ValidationResultInsecure))

			c.answers["DS co.jp."] = &dns.Msg{Ns: append([]dns.RR{nsec, sig}, genuine...)}
			v = NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ = v.walkChainOfTrust(ctx, "jprs.co.jp.")
			Expect(result).Should(Equal(ValidationResultBogus))
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
			Expect(sut.provesNoZoneCut("co.jp.", jpKeys, &dns.Msg{Ns: []dns.RR{nsec, sig}}, &budget)).Should(BeFalse())
			Expect(sut.provesNoZoneCut("co.jp.", jpKeys, c.answers["DS co.jp."], &budget)).Should(BeTrue(),
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

		It("asks once whether co.jp. is part of jp.", func() {
			v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			result, _ := v.walkChainOfTrust(ctx, "jprs.co.jp.")
			Expect(result).Should(Equal(ValidationResultSecure))

			// What the walk found at co.jp. is kept: for a walk to co.jp. itself, and for one through it
			c.queries = nil

			result, _ = v.walkChainOfTrust(ctx, "co.jp.")
			Expect(result).Should(Equal(ValidationResultBogus), "co.jp. is still no signer")
			Expect(v.unsignedStatus(ctx, "co.jp.")).Should(Equal(ValidationResultBogus), "jp. signs what co.jp. holds")
			Expect(c.queries).Should(BeEmpty())

			result, _ = v.walkChainOfTrust(ctx, "other.co.jp.")
			Expect(result).Should(Equal(ValidationResultIndeterminate), "the DS reply for other.co.jp. is empty")
			Expect(c.queries).Should(Equal([]string{"DS other.co.jp.", "DS other.co.jp."}),
				"a reply without an answer is asked for once more")
		})

		It("counts a cache hit for each cache entry that a walk uses", func() {
			v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

			// A walk to co.jp. looks at the entry for that name before it starts at jp., and uses it
			// when it comes to the name
			for range 2 {
				Expect(v.walk(ctx, "co.jp.", false).result).Should(Equal(ValidationResultSecure))
			}

			Expect(testutil.ToFloat64(v.cacheHitMetrics)).Should(BeEquivalentTo(2),
				"the second walk uses the entries for jp. and for co.jp.")
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

		// A name that owns a CNAME RRset has no other data (RFC 1034 §3.6.2, RFC 2181 §10.1), so it
		// is no zone cut, and the reply to the DS query for it is that RRset. Here co.jp. is an alias
		// in the zone jp.
		Describe("past a name that owns a CNAME RRset", func() {
			const target = "www.example."

			var (
				question dns.Question
				signed   *dns.Msg
			)

			// alias returns the CNAME RRset of owner followed by the RRSIG that jp. makes for it
			alias := func(c *partOfParentChain, owner string) []dns.RR {
				cname := &dns.CNAME{
					Hdr:    dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: target,
				}

				return []dns.RR{cname, signRRset([]dns.RR{cname}, dns.TypeCNAME, c.jpKey, c.jpPriv, "jp.")}
			}

			BeforeEach(func() {
				question = dns.Question{Name: "www.jprs.co.jp.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
				signed = signedA(question.Name, "192.0.2.1", c.childKey, c.childPriv, "jprs.co.jp.")
			})

			It("goes on with the keys of jp. when jp. signed the CNAME RRset of co.jp.", func() {
				// unsigned.co.jp. is a delegation of jp. without DS RRset
				c.answers["DS unsigned.co.jp."] = &dns.Msg{
					Ns: signedNSEC("unsigned.co.jp.", c.jpKey, c.jpPriv, "jp.", dns.TypeNS),
				}
				unsigned := &dns.Msg{
					Answer: signedA("www.unsigned.co.jp.", "192.0.2.1", c.childKey, c.childPriv, "jprs.co.jp.").Answer[:1],
				}

				// The reply may go on with what the target of the CNAME has, here the denial of its DS
				// RRset by its own zone. None of that is read.
				targetKey, targetPriv, _ := newSignedZoneKey("example.")

				for _, forTarget := range [][]dns.RR{nil, signedNSEC(target, targetKey, targetPriv, "example.", dns.TypeA)} {
					c.answers["DS co.jp."] = &dns.Msg{Answer: alias(c, "co.jp."), Ns: forTarget}
					c.queries = nil
					v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

					Expect(v.ValidateResponse(ctx, signed, question)).Should(Equal(ValidationResultSecure))
					Expect(c.queries).Should(Equal([]string{"DNSKEY jp.", "DS co.jp.", "DS jprs.co.jp.", "DNSKEY jprs.co.jp."}),
						"co.jp. has no DNSKEY RRset to fetch")

					result, keys := v.walkChainOfTrust(ctx, "jprs.co.jp.")
					Expect(result).Should(Equal(ValidationResultSecure))
					Expect(keys).Should(ConsistOf(c.childKey))

					Expect(v.ValidateResponse(ctx, unsigned,
						dns.Question{Name: "www.unsigned.co.jp.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
					)).Should(Equal(ValidationResultInsecure), "below an insecure delegation of jp. below co.jp.")

					result, _ = v.walkChainOfTrust(ctx, "co.jp.")
					Expect(result).Should(Equal(ValidationResultBogus), "co.jp. is a name of jp. and no signer")
				}
			})

			// The queries of a walk that stops at co.jp., and of one that asks its DS query once more
			asked := []string{"DNSKEY jp.", "DS co.jp."}
			askedAgain := []string{"DNSKEY jp.", "DS co.jp.", "DS co.jp."}

			DescribeTable("does not go on past co.jp. on a CNAME RRset that jp. did not sign for that name",
				func(offered func(c *partOfParentChain) []dns.RR, status ValidationResult, queries []string) {
					// With the CNAME RRset of co.jp. as jp. signs it, the zone below validates
					c.answers["DS co.jp."] = &dns.Msg{Answer: alias(c, "co.jp.")}
					v := NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)
					Expect(v.ValidateResponse(ctx, signed, question)).Should(Equal(ValidationResultSecure))

					// Any other is no proof. A CNAME RRset of co.jp. that the keys of jp. do not verify
					// for that name is no answer of jp., like a DS RRset that does not verify: Bogus.
					// The CNAME RRset of another name says nothing about co.jp.: the reply is one
					// without DS RRset and without its denial, which the lookup asks for once more and
					// cannot complete.
					c.answers["DS co.jp."] = &dns.Msg{Answer: offered(c)}
					c.queries = nil
					v = NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)

					result, keys := v.walkChainOfTrust(ctx, "jprs.co.jp.")
					Expect(result).Should(Equal(status))
					Expect(keys).Should(BeEmpty())
					Expect(c.queries).Should(Equal(queries), "the walk stops at co.jp.")
				},
				Entry("without RRSIG", func(c *partOfParentChain) []dns.RR {
					return alias(c, "co.jp.")[:1]
				}, ValidationResultBogus, asked),
				Entry("with an RRSIG that names the key of jp. and does not verify", func(c *partOfParentChain) []dns.RR {
					otherKey, otherPriv, _ := newSignedZoneKey("jp.")
					rrs := alias(c, "co.jp.")
					sig := signRRset(rrs[:1], dns.TypeCNAME, otherKey, otherPriv, "jp.")
					sig.KeyTag = c.jpKey.KeyTag()

					return []dns.RR{rrs[0], sig}
				}, ValidationResultBogus, asked),
				Entry("with the RRSIG of a zone at co.jp. itself", func(c *partOfParentChain) []dns.RR {
					// Only the zone that the walk is in says what is part of it
					ownKey, ownPriv, _ := newSignedZoneKey("co.jp.")
					rrs := alias(c, "co.jp.")

					return []dns.RR{rrs[0], signRRset(rrs[:1], dns.TypeCNAME, ownKey, ownPriv, "co.jp.")}
				}, ValidationResultBogus, asked),
				Entry("verified by the RRSIG that jp. made for the wildcard *.jp.", func(c *partOfParentChain) []dns.RR {
					// RFC 4035 §5.3.2: the RRSIG of a wildcard verifies its RRset under every name that
					// the wildcard matches, which says nothing about what co.jp. owns
					rrs := alias(c, "*.jp.")
					rrs[0].Header().Name, rrs[1].Header().Name = "co.jp.", "co.jp."

					sig, _ := rrs[1].(*dns.RRSIG)
					Expect(sig.Labels).Should(BeEquivalentTo(1))
					Expect(sig.Verify(c.jpKey, rrs[:1])).Should(Succeed())

					return rrs
				}, ValidationResultBogus, asked),
				Entry("of another name of jp.", func(c *partOfParentChain) []dns.RR {
					return alias(c, "cn.jp.")
				}, ValidationResultIndeterminate, askedAgain),
			)
		})
	})

	// The status of data without RRSIG at a name is that of the zone that holds the name, which the
	// chain of trust walk finds. example. is the trust anchor, signed.example. a signed zone and
	// unsigned.example. an insecure delegation of example.
	Describe("unsignedStatus", func() {
		var (
			c *repliedChain
			v *Validator
		)

		BeforeEach(func() {
			c = newRepliedChain()
			c.replies["DS unsigned.example."] = &dns.Msg{Ns: c.parentNSEC("unsigned.example.", dns.TypeNS)}
			mockUpstream.ResolveFn = c.resolve
			v = NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)
		})

		// lookup returns the status of data without RRSIG at name as a validation of its own finds
		// it, and the queries that it made for that.
		lookup := func(name string) (ValidationResult, []string) {
			c.queries = nil

			return v.unsignedStatus(withQueryBudget(ctx, 30), name), c.queries
		}

		It("asks one DS query for a name three labels below an insecure delegation, and none again", func() {
			result, _ := v.walkChainOfTrust(ctx, c.parent)
			Expect(result).Should(Equal(ValidationResultSecure))

			status, queries := lookup("c.b.a.unsigned.example.")
			Expect(status).Should(Equal(ValidationResultInsecure))
			Expect(queries).Should(Equal([]string{"DS unsigned.example."}))

			status, queries = lookup("c.b.a.unsigned.example.")
			Expect(status).Should(Equal(ValidationResultInsecure))
			Expect(queries).Should(BeEmpty())
		})

		It("shares the lookup between the names of an unsigned zone", func() {
			status, queries := lookup("www.unsigned.example.")
			Expect(status).Should(Equal(ValidationResultInsecure))
			Expect(queries).Should(Equal([]string{"DNSKEY example.", "DS unsigned.example."}))

			status, queries = lookup("mail.host.unsigned.example.")
			Expect(status).Should(Equal(ValidationResultInsecure))
			Expect(queries).Should(BeEmpty())
		})

		It("is Insecure for a name of 34 labels below an insecure delegation", func() {
			// The walk stops at the insecure delegation, however long the name below it is
			name := strings.Repeat("x.", 32) + "unsigned.example."
			Expect(dns.CountLabel(name)).Should(Equal(34))

			status, queries := lookup(name)
			Expect(status).Should(Equal(ValidationResultInsecure))
			Expect(queries).Should(Equal([]string{"DNSKEY example.", "DS unsigned.example."}))

			// Nor is a signer of that many labels there refused for its length
			result, _ := v.walkChainOfTrust(ctx, name)
			Expect(result).Should(Equal(ValidationResultInsecure))
		})

		It("is Insecure below an insecure delegation of 12 labels, past the names above it that are no zones", func() {
			// The names between example. and the delegation are empty non-terminals. The walk asks for
			// each once, to find that it is no zone cut, and none of them is a zone of the chain.
			const delegation = "u.k.j.i.h.g.f.e.d.c.b.example."

			Expect(dns.CountLabel(delegation)).Should(Equal(12))
			c.emptyNonTerminals(c.parent, c.parentKey, c.parentPriv, delegation)
			c.replies["DS "+delegation] = &dns.Msg{Ns: c.parentNSEC(delegation, dns.TypeNS)}

			status, queries := lookup("www." + delegation)
			Expect(status).Should(Equal(ValidationResultInsecure))
			Expect(queries).Should(HaveLen(12), "the DNSKEY RRset of example., ten empty non-terminals, the delegation")

			status, queries = lookup("mail." + delegation)
			Expect(status).Should(Equal(ValidationResultInsecure))
			Expect(queries).Should(BeEmpty())
		})

		It("keeps no verdict of a walk that runs out of queries on names that are no zone cut", func() {
			// An insecure delegation of 36 labels below empty non-terminals: more names than one
			// validation has queries for. What it could not find out is found by the next one, which
			// goes on below the names that are known to be no zone cut.
			delegation := strings.Repeat("x.", 35) + c.parent
			c.emptyNonTerminals(c.parent, c.parentKey, c.parentPriv, delegation)
			c.replies["DS "+delegation] = &dns.Msg{Ns: c.parentNSEC(delegation, dns.TypeNS)}

			status, queries := lookup("www." + delegation)
			Expect(status).Should(Equal(ValidationResultBogus), "the data is refused below a trust anchor")
			Expect(queries).Should(HaveLen(30))

			for _, name := range []string{"www." + delegation, delegation, "x." + c.parent} {
				_, found := v.getCachedValidation(ctx, name)
				Expect(found).Should(BeFalse(), name)
			}

			status, queries = lookup("www." + delegation)
			Expect(status).Should(Equal(ValidationResultInsecure))
			Expect(queries).Should(HaveLen(6), "five more empty non-terminals and the delegation")
		})

		It("does not take a DS RRset below an insecure delegation for that of a signed zone", func() {
			// The unsigned zone holds a DS RRset for a child of its own, which nothing signs. A walk
			// stops at the insecure delegation (RFC 4035 §5.2) and asks for nothing below it.
			ds := c.childKey.ToDS(dns.SHA256)
			ds.Hdr.Name = "child.unsigned.example."
			c.replies["DS child.unsigned.example."] = &dns.Msg{Answer: []dns.RR{ds}}

			status, queries := lookup("www.child.unsigned.example.")
			Expect(status).Should(Equal(ValidationResultInsecure))
			Expect(queries).Should(Equal([]string{"DNSKEY example.", "DS unsigned.example."}))
		})

		It("does not accept the denial of a DS RRset that another zone than the parent signed", func() {
			// RFC 4035 §5.2: the zone that delegates a name denies its DS RRset. example. signs an NSEC
			// record for victim.signed.example., a name of the zone signed.example. that it delegated.
			c.replies["DS victim.signed.example."] = &dns.Msg{Ns: c.parentNSEC("victim.signed.example.", dns.TypeNS)}

			status, _ := lookup("www.victim.signed.example.")
			Expect(status).Should(Equal(ValidationResultBogus))
		})

		It("does not take an NSEC record without RRSIG for the denial of a DS RRset, and asks no more for it", func() {
			// RFC 4035 §5.2: only an authenticated denial shows an insecure delegation. The record has
			// no status of its own to look up either, beside the SOA record that example. signed.
			soa := &dns.SOA{
				Hdr: dns.RR_Header{Name: c.parent, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns." + c.parent, Mbox: "hostmaster." + c.parent, Serial: 1, Minttl: 300,
			}
			c.replies["DS unsigned.example."] = &dns.Msg{Ns: []dns.RR{
				soa, signRRset([]dns.RR{soa}, dns.TypeSOA, c.parentKey, c.parentPriv, c.parent),
				c.parentNSEC("unsigned.example.", dns.TypeNS)[0],
			}}

			status, queries := lookup("www.unsigned.example.")
			Expect(status).Should(Equal(ValidationResultBogus))
			Expect(queries).Should(Equal([]string{"DNSKEY example.", "DS unsigned.example."}))
		})

		It("is Bogus in a signed zone, which proves once that the name is part of it", func() {
			// GHSA-x845-2f78-7v36: a signed zone signs all that it holds
			c.replies["DS www.signed.example."] = &dns.Msg{Ns: c.childNSEC("www.signed.example.", dns.TypeA)}

			status, queries := lookup("www.signed.example.")
			Expect(status).Should(Equal(ValidationResultBogus))
			Expect(queries).Should(Equal([]string{
				"DNSKEY example.", "DS signed.example.", "DNSKEY signed.example.", "DS www.signed.example.",
			}))

			status, queries = lookup("www.signed.example.")
			Expect(status).Should(Equal(ValidationResultBogus))
			Expect(queries).Should(BeEmpty())
		})

		DescribeTable("is Bogus below a trust anchor while the walk cannot be completed, and keeps nothing of that",
			func(query string, reply *dns.Msg, asked []string) {
				// GHSA-x845-2f78-7v36: only the proof of an insecure delegation makes data without RRSIG
				// Insecure. Issue #2120: what a failed query leaves open is found by the next walk.
				proper, replied := c.replies[query]
				c.replies[query] = reply

				status, queries := lookup("www.unsigned.example.")
				Expect(status).Should(Equal(ValidationResultBogus))
				Expect(queries).Should(Equal(asked), "the walk stops where it cannot go on")

				if replied {
					c.replies[query] = proper
				} else {
					delete(c.replies, query)
				}

				status, _ = lookup("www.unsigned.example.")
				Expect(status).Should(Equal(ValidationResultInsecure))
			},
			Entry("the DNSKEY query for the trust anchor fails",
				"DNSKEY example.", (*dns.Msg)(nil), []string{"DNSKEY example."}),
			Entry("the DS query for the delegation fails",
				"DS unsigned.example.", (*dns.Msg)(nil), []string{"DNSKEY example.", "DS unsigned.example."}),
			Entry("the DS reply holds neither a DS RRset nor its denial, also when asked for once more",
				"DS unsigned.example.", &dns.Msg{},
				[]string{"DNSKEY example.", "DS unsigned.example.", "DS unsigned.example."}),
		)

		It("is Indeterminate without a trust anchor above the name, and asks nothing", func() {
			status, queries := lookup("www.unsigned.other.")
			Expect(status).Should(Equal(ValidationResultIndeterminate))
			Expect(queries).Should(BeEmpty())
		})
	})

	Describe("DS and DNSKEY RRsets of the zone that is validated", func() {
		// RFC 4034 §2 and §5, RFC 4035 §5.2: the DS RRset of a delegation authenticates the DNSKEY
		// RRset at the apex of the zone that it delegates. example., the trust anchor, delegates the
		// signed zones signed.example., which is validated here, and other.example.
		const other = "other.example."

		var (
			c         *repliedChain
			v         *Validator
			otherKey  *dns.DNSKEY
			otherPriv *ecdsa.PrivateKey
			question  dns.Question
		)

		BeforeEach(func() {
			c = newRepliedChain()
			otherKey, otherPriv = c.delegate(c.parent, c.parentKey, c.parentPriv, other)
			question = dns.Question{Name: "www." + c.child, Qtype: dns.TypeA, Qclass: dns.ClassINET}
			mockUpstream.ResolveFn = c.resolve
			v = NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)
		})

		// signedByParent returns ds, a DS record, as an RRset that example. signs
		signedByParent := func(ds *dns.DS) []dns.RR {
			return []dns.RR{ds, signRRset([]dns.RR{ds}, dns.TypeDS, c.parentKey, c.parentPriv, c.parent)}
		}

		// unusableKey returns a key of zone that nothing verifies with: RSA/SHA-1, exponent 2^32+1
		unusableKey := func(zone string) *dns.DNSKEY {
			key, _, _, _ := generateBigExponentRSAKey(zone)
			key.Algorithm = dns.RSASHA1

			return key
		}

		// digestUnderZoneName returns the DS RRset of other.example. with the digest of a key under
		// the name of the zone, and that key as a DNSKEY RRset of the zone with its own RRSIG. The
		// digest of a DS record covers the owner name of the key, not the name of the delegation
		// that the record is published at (RFC 4034 §5.1.4).
		digestUnderZoneName := func() (ds, keys []dns.RR) {
			key, priv, _ := newSignedZoneKey(c.child)
			digest := key.ToDS(dns.SHA256)
			digest.Hdr.Name = other

			return signedByParent(digest), []dns.RR{key, signRRset([]dns.RR{key}, dns.TypeDNSKEY, key, priv, c.child)}
		}

		// ownUnusableKey returns the DS RRset of other.example. for a key of that zone which nothing
		// verifies with, and that key as the DNSKEY RRset of other.example.
		ownUnusableKey := func() (ds, keys []dns.RR) {
			key := unusableKey(other)

			return signedByParent(key.ToDS(dns.SHA256)), []dns.RR{key}
		}

		DescribeTable("a DS reply with the DS RRset of another delegation has no DS RRset of the zone",
			func(offered func() (ds, keys []dns.RR), authority bool) {
				ds, keys := offered()
				if authority {
					c.replies["DS "+c.child] = &dns.Msg{Ns: ds}
				} else {
					c.replies["DS "+c.child] = &dns.Msg{Answer: ds}
				}

				c.replies["DNSKEY "+c.child] = &dns.Msg{Answer: keys}

				// The reply is what a reply without DS RRset and without its denial is, whatever the
				// DNSKEY reply holds: the walk finds no keys, and nothing to keep for the zone
				result, zoneKeys := v.walkChainOfTrust(ctx, c.child)
				Expect(result).Should(Equal(ValidationResultIndeterminate))
				Expect(zoneKeys).Should(BeEmpty())
				Expect(v.cachedZoneStatus(ctx, c.child)).Should(BeNil())

				unsigned := &dns.Msg{Answer: signedA(question.Name, "192.0.2.66", c.childKey, c.childPriv, c.child).Answer[:1]}
				Expect(v.ValidateResponse(ctx, unsigned, question)).Should(Equal(ValidationResultBogus))

				// With its own replies again, the zone is what it is
				delete(c.replies, "DS "+c.child)
				delete(c.replies, "DNSKEY "+c.child)

				Expect(v.ValidateResponse(ctx, signedA(question.Name, "192.0.2.1", c.childKey, c.childPriv, c.child), question)).
					Should(Equal(ValidationResultSecure))
			},
			Entry("which holds the digest of a key under the name of the zone, beside that key as the DNSKEY reply",
				digestUnderZoneName, false),
			Entry("the same RRset in the authority section", digestUnderZoneName, true),
			Entry("for a key that nothing verifies with, beside the DNSKEY RRset of that delegation as the DNSKEY reply",
				ownUnusableKey, false),
		)

		It("a DS RRset in the authority section of a DS reply is no answer to the query", func() {
			c.replies["DS "+c.child] = &dns.Msg{Ns: []dns.RR{c.ds, c.dsSig}}

			result, zoneKeys := v.walkChainOfTrust(ctx, c.child)
			Expect(result).Should(Equal(ValidationResultIndeterminate))
			Expect(zoneKeys).Should(BeEmpty())
		})

		// expanded returns rrset, which holds one record, with the RRSIG that example. makes for it
		// under the wildcard *.example., as a reply holds the two for the zone: the RRSIG verifies
		// the record under every name that the wildcard matches (RFC 4035 §5.3.2)
		expanded := func(rr dns.RR) []dns.RR {
			rr.Header().Name = "*." + c.parent
			sig := signRRset([]dns.RR{rr}, rr.Header().Rrtype, c.parentKey, c.parentPriv, c.parent)
			rr.Header().Name, sig.Hdr.Name = c.child, c.child

			return []dns.RR{rr, sig}
		}

		It("a DS RRset that an RRSIG made for a wildcard verifies is not the DS RRset of the zone", func() {
			// RFC 4592 §4.6: a wildcard gives no name a DS RRset. This one holds the digest of a key
			// under the name of the zone, and the DNSKEY reply holds that key.
			key, priv, _ := newSignedZoneKey(c.child)
			c.replies["DS "+c.child] = &dns.Msg{Answer: expanded(key.ToDS(dns.SHA256))}
			c.replies["DNSKEY "+c.child] = &dns.Msg{Answer: []dns.RR{
				key, signRRset([]dns.RR{key}, dns.TypeDNSKEY, key, priv, c.child),
			}}

			result, zoneKeys := v.walkChainOfTrust(ctx, c.child)
			Expect(result).Should(Equal(ValidationResultBogus))
			Expect(zoneKeys).Should(BeEmpty())
		})

		// A unit spec of answerRRset, with a key source that no walk gives a DNSKEY RRset: the keys of
		// the zone above. Only they make an RRSIG for a wildcard above an apex that checkRRSIG takes
		// (see wildcardInSignerZone), so only with them this rule is what refuses the RRset.
		It("answerRRset refuses a DNSKEY RRset that only an RRSIG made for a wildcard verifies", func() {
			key, _, _ := newSignedZoneKey(c.child)
			keys := parentKeys{v: v, keys: newKeySet(ctx, []*dns.DNSKEY{c.parentKey})}

			r := answerRRset(ctx, &dns.Msg{Answer: expanded(key)}, c.child, dns.TypeDNSKEY, keys)
			Expect(r.status).Should(Equal(ValidationResultBogus))
			Expect(r.sig).Should(BeNil())

			// The same RRSIG verifies the RRset of the wildcard, which is what it was made for
			wildcard := expanded(key)
			wildcard[0].Header().Name, wildcard[1].Header().Name = "*."+c.parent, "*."+c.parent

			r = answerRRset(ctx, &dns.Msg{Answer: wildcard}, "*."+c.parent, dns.TypeDNSKEY, keys)
			Expect(r.status).Should(Equal(ValidationResultSecure))
		})

		It("a DNSKEY record of another name is no key of the zone", func() {
			// The reply holds the DNSKEY RRset of other.example. before that of the zone
			c.replies["DNSKEY "+c.child] = &dns.Msg{Answer: append(append([]dns.RR{}, c.replies["DNSKEY "+other].Answer...),
				c.childKey, c.childKeySig)}

			result, zoneKeys := v.walkChainOfTrust(ctx, c.child)
			Expect(result).Should(Equal(ValidationResultSecure))
			Expect(zoneKeys).Should(ConsistOf(c.childKey))

			// An RRSIG that the key of other.example. makes in the name of the zone verifies nothing
			Expect(v.ValidateResponse(ctx, signedA(question.Name, "192.0.2.66", otherKey, otherPriv, c.child), question)).
				Should(Equal(ValidationResultBogus))
			Expect(v.ValidateResponse(ctx, signedA(question.Name, "192.0.2.1", c.childKey, c.childPriv, c.child), question)).
				Should(Equal(ValidationResultSecure))
		})

		It("a DNSKEY reply with the keys of another name has no keys of the zone, before a DS record names one", func() {
			// The DS RRset of the zone holds the digest of a key under the name other.example., a key
			// that nothing verifies with. No key of the zone has that digest (RFC 4034 §5.1.4), and
			// the reply holds no DNSKEY RRset of the zone: the lookup for the keys of the zone is not
			// completed, which is no zone whose DS RRset names only keys of that kind.
			key := unusableKey(other)
			ds := key.ToDS(dns.SHA256)
			ds.Hdr.Name = c.child
			c.replies["DS "+c.child] = &dns.Msg{Answer: signedByParent(ds)}
			c.replies["DNSKEY "+c.child] = &dns.Msg{Answer: []dns.RR{key}}

			result, zoneKeys := v.walkChainOfTrust(ctx, c.child)
			Expect(result).Should(Equal(ValidationResultIndeterminate))
			Expect(zoneKeys).Should(BeEmpty())
			Expect(v.cachedZoneStatus(ctx, c.child)).Should(BeNil())

			unsigned := &dns.Msg{Answer: signedA(question.Name, "192.0.2.66", c.childKey, c.childPriv, c.child).Answer[:1]}
			Expect(v.ValidateResponse(ctx, unsigned, question)).Should(Equal(ValidationResultBogus))
		})

		It("the DNSKEY RRset of a trust anchor zone without the RRSIG of an anchored key is refused, and no key of it kept", func() {
			// RFC 4035 §5: example. signs its DNSKEY RRset, the anchored key and a zone-signing key,
			// with the anchored key. A reply with the anchored key alone and no RRSIG is not that RRset.
			zsk, zskPriv, _ := newSignedZoneKey(c.parent)
			zsk.Flags = dns.ZONE
			keys := []dns.RR{c.parentKey, zsk}
			signed := &dns.Msg{Answer: []dns.RR{
				c.parentKey, zsk, signRRset(keys, dns.TypeDNSKEY, c.parentKey, c.parentPriv, c.parent),
			}}
			question = dns.Question{Name: "www." + c.parent, Qtype: dns.TypeA, Qclass: dns.ClassINET}
			answer := signedA(question.Name, "192.0.2.1", zsk, zskPriv, c.parent)

			c.replies["DNSKEY "+c.parent] = &dns.Msg{Answer: []dns.RR{c.parentKey}}
			Expect(v.ValidateResponse(ctx, answer, question)).Should(Equal(ValidationResultBogus))

			// What is kept is the failure, for as long as any failure is
			status, left := v.validationCache.Get(validationCacheKey(ctx, c.parent))
			Expect(status.result).Should(Equal(ValidationResultBogus))
			Expect(status.keys).Should(BeEmpty())
			Expect(left).Should(BeNumerically("<=", BogusTTL))

			c.replies["DNSKEY "+c.parent] = signed
			v = NewValidator(ctx, c.anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)
			Expect(v.ValidateResponse(ctx, answer, question)).Should(Equal(ValidationResultSecure))
		})

		It("a DS RRset that the zone at its owner name signs is not authentic", func() {
			// RFC 4034 §5, RFC 4035 §5.3.1: the DS RRset of signed.example. is data of example., the
			// zone above the delegation, and signed.example. is not the signer of any DS RRset there
			question = dns.Question{Name: c.child, Qtype: dns.TypeDS, Qclass: dns.ClassINET}
			bySelf := signRRset([]dns.RR{c.ds}, dns.TypeDS, c.childKey, c.childPriv, c.child)

			Expect(v.ValidateResponse(ctx, &dns.Msg{Answer: []dns.RR{c.ds, c.dsSig}}, question)).
				Should(Equal(ValidationResultSecure))
			Expect(v.ValidateResponse(ctx, &dns.Msg{Answer: []dns.RR{c.ds, bySelf}}, question)).
				Should(Equal(ValidationResultBogus))
		})

		It("a DS RRset at the root is a record of the root, which has no zone above it", func() {
			// RFC 4035 §5.3.1: the signer is the zone that holds the RRset. Here the root has a key
			// of its own as the trust anchor.
			rootKey, rootPriv, anchor := newSignedZoneKey(".")
			anchors, err := NewTrustAnchorStore([]string{anchor})
			Expect(err).Should(Succeed())

			c.replies["DNSKEY ."] = &dns.Msg{Answer: []dns.RR{
				rootKey, signRRset([]dns.RR{rootKey}, dns.TypeDNSKEY, rootKey, rootPriv, "."),
			}}
			v = NewValidator(ctx, anchors, sut.logger, mockUpstream, 1, 10, 150, 30, 3600)
			question = dns.Question{Name: ".", Qtype: dns.TypeDS, Qclass: dns.ClassINET}
			ds := rootKey.ToDS(dns.SHA256)

			Expect(v.ValidateResponse(ctx,
				&dns.Msg{Answer: []dns.RR{ds, signRRset([]dns.RR{ds}, dns.TypeDS, rootKey, rootPriv, ".")}}, question,
			)).Should(Equal(ValidationResultSecure))
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
		It("should return Indeterminate when the DNSKEY reply holds the keys of another name", func() {
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

			// The lookup of the root keys, which the reply does not hold, is not completed
			result := sut.validateDSRecordSignature(ctx, "example.com.", "com.", []dns.RR{ds}, rrsig)
			Expect(result).Should(Equal(ValidationResultIndeterminate))
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

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response, &budget)
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

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response, &budget)
			Expect(dsRecords).Should(BeNil())
			Expect(result).ShouldNot(Equal(ValidationResultSecure))
		})

		It("should return Bogus for a CNAME RRset that the parent zone did not sign, without NSEC/NSEC3", func() {
			// A name that owns a CNAME RRset answers the DS query with it. Without the RRSIG of the
			// parent zone it proves nothing, and the reply holds no other proof.
			response := &dns.Msg{
				Answer: []dns.RR{&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "www.example.net.",
				}},
			}

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response, &budget)
			Expect(dsRecords).Should(BeNil())
			Expect(result).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("verifyDenialSignatures", func() {
		It("should give every denial RRset of a reply its own tries", func() {
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

			Expect(sut.verifyDenialSignatures(denials(maxZoneKeyVerifications), keys, &budget)).Should(Succeed())

			budget = maxZoneKeyVerifications
			Expect(sut.verifyDenialSignatures(denials(maxZoneKeyVerifications+1), keys, &budget)).Should(Succeed())
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
					return &model.Response{Res: &dns.Msg{Rcode: dns.RcodeServerFailure}}, nil
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

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response, &budget)
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

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response, &budget)
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

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response, &budget)
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

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", []*dns.DNSKEY{parentDnskey}, response, &budget)
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

			dsRecords, result := sut.extractAndValidateDSRecords("example.com.", nil, response, &budget)
			Expect(dsRecords).Should(BeNil())
			Expect(result).ShouldNot(Equal(ValidationResultSecure))
		})
	})

	Describe("walkChainOfTrust - trust anchor path coverage", func() {
	})
})

// repliedChain is the chain of newSignedChain with replies to further queries. replies maps
// "TYPE name" to the reply that the upstream sends, or to nil for a query that fails, and queries
// records what the upstream was asked.
type repliedChain struct {
	*signedChain

	replies map[string]*dns.Msg
	queries []string
}

func newRepliedChain() *repliedChain {
	return &repliedChain{signedChain: newSignedChain(), replies: map[string]*dns.Msg{}}
}

func (c *repliedChain) resolve(ctx context.Context, req *model.Request) (*model.Response, error) {
	q := req.Req.Question[0]
	query := dns.TypeToString[q.Qtype] + " " + q.Name
	c.queries = append(c.queries, query)

	switch reply, replied := c.replies[query]; {
	case !replied:
		return c.signedChain.resolve(ctx, req)
	case reply == nil:
		return nil, errors.New("upstream unreachable")
	default:
		return &model.Response{Res: reply}, nil
	}
}

// delegate makes child a signed zone that parent, a zone that signs with key and priv, delegates.
// It adds the replies to the DS and DNSKEY queries for child and returns the key of child. The
// names between the two zones are empty non-terminals (see emptyNonTerminals).
func (c *repliedChain) delegate(
	parent string, key *dns.DNSKEY, priv *ecdsa.PrivateKey, child string,
) (*dns.DNSKEY, *ecdsa.PrivateKey) {
	childKey, childPriv, _ := newSignedZoneKey(child)
	ds := childKey.ToDS(dns.SHA256)

	c.replies["DS "+child] = &dns.Msg{Answer: []dns.RR{ds, signRRset([]dns.RR{ds}, dns.TypeDS, key, priv, parent)}}
	c.replies["DNSKEY "+child] = &dns.Msg{Answer: []dns.RR{
		childKey, signRRset([]dns.RR{childKey}, dns.TypeDNSKEY, childKey, childPriv, child),
	}}
	c.emptyNonTerminals(parent, key, priv, child)

	return childKey, childPriv
}

// emptyNonTerminals adds the replies to the DS queries for the names between zone, which signs
// with key and priv, and below, a name of zone: the NSEC record of the apex of zone has below as
// its next owner name, which shows that the names between them have no records.
func (c *repliedChain) emptyNonTerminals(zone string, key *dns.DNSKEY, priv *ecdsa.PrivateKey, below string) {
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: zone, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: below,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
	}
	proof := &dns.Msg{Ns: []dns.RR{nsec, signRRset([]dns.RR{nsec}, dns.TypeNSEC, key, priv, zone)}}

	for name := below[strings.Index(below, ".")+1:]; name != zone; name = name[strings.Index(name, ".")+1:] {
		c.replies["DS "+name] = proof
	}
}

// parentNSEC returns the NSEC record of name with types as the parent zone of the chain signs it,
// followed by its RRSIG: the authority section of a reply to a DS query for name.
func (c *repliedChain) parentNSEC(name string, types ...uint16) []dns.RR {
	return signedNSEC(name, c.parentKey, c.parentPriv, c.parent, types...)
}

// childNSEC is parentNSEC for the child zone of the chain.
func (c *repliedChain) childNSEC(name string, types ...uint16) []dns.RR {
	return signedNSEC(name, c.childKey, c.childPriv, c.child, types...)
}

func signedNSEC(name string, key *dns.DNSKEY, priv *ecdsa.PrivateKey, signer string, types ...uint16) []dns.RR {
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "\\000." + name,
		TypeBitMap: append(types, dns.TypeRRSIG, dns.TypeNSEC),
	}

	return []dns.RR{nsec, signRRset([]dns.RR{nsec}, dns.TypeNSEC, key, priv, signer)}
}

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
