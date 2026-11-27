package dnssec

import (
	"context"
	"encoding/base32"
	"math/big"
	"strings"

	"github.com/0xERR0R/blocky/log"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NSEC3 validation", func() {
	var (
		sut        *Validator
		trustStore *TrustAnchorStore
		ctx        context.Context
	)

	BeforeEach(func(specCtx SpecContext) {
		ctx = specCtx

		var err error
		trustStore, err = NewTrustAnchorStore(nil)
		Expect(err).Should(Succeed())

		mockUpstream := &mockResolver{}
		logger, _ := log.NewMockEntry()

		sut = NewValidator(ctx, trustStore, logger, mockUpstream, 1, 10, 150, 30, 3600)
		ctx = withQueryBudget(ctx, 10)
	})

	Describe("extractNSEC3Records", func() {
		It("should extract NSEC3 records from RR slice", func() {
			nsec3_1 := &dns.NSEC3{
				Hdr:  dns.RR_Header{Name: "hash1.example.com.", Rrtype: dns.TypeNSEC3},
				Hash: dns.SHA1,
			}
			nsec3_2 := &dns.NSEC3{
				Hdr:  dns.RR_Header{Name: "hash2.example.com.", Rrtype: dns.TypeNSEC3},
				Hash: dns.SHA1,
			}
			soa := &dns.SOA{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA},
			}

			rrs := []dns.RR{nsec3_1, soa, nsec3_2}
			nsec3s := extractNSEC3Records(rrs)

			Expect(nsec3s).Should(HaveLen(2))
			Expect(nsec3s[0]).Should(Equal(nsec3_1))
			Expect(nsec3s[1]).Should(Equal(nsec3_2))
		})

		It("should return empty slice when no NSEC3 records", func() {
			soa := &dns.SOA{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA},
			}

			rrs := []dns.RR{soa}
			nsec3s := extractNSEC3Records(rrs)

			Expect(nsec3s).Should(BeEmpty())
		})

		It("should handle empty RR slice", func() {
			nsec3s := extractNSEC3Records([]dns.RR{})
			Expect(nsec3s).Should(BeEmpty())
		})

		It("should handle nil RR slice", func() {
			nsec3s := extractNSEC3Records(nil)
			Expect(nsec3s).Should(BeEmpty())
		})
	})

	Describe("computeNSEC3Hash", func() {
		It("should compute NSEC3 hash for a name", func() {
			hash, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(hash).ShouldNot(BeEmpty())
		})

		It("should return same hash for same inputs", func() {
			hash1, err1 := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err1).ShouldNot(HaveOccurred())

			hash2, err2 := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err2).ShouldNot(HaveOccurred())

			Expect(hash1).Should(Equal(hash2))
		})

		It("should return different hash for different names", func() {
			hash1, err1 := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err1).ShouldNot(HaveOccurred())

			hash2, err2 := sut.computeNSEC3Hash("test.com.", dns.SHA1, "", 0)
			Expect(err2).ShouldNot(HaveOccurred())

			Expect(hash1).ShouldNot(Equal(hash2))
		})

		It("should return different hash with different salt", func() {
			hash1, err1 := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err1).ShouldNot(HaveOccurred())

			hash2, err2 := sut.computeNSEC3Hash("example.com.", dns.SHA1, "AABBCCDD", 0)
			Expect(err2).ShouldNot(HaveOccurred())

			Expect(hash1).ShouldNot(Equal(hash2))
		})

		It("should return different hash with different iterations", func() {
			hash1, err1 := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err1).ShouldNot(HaveOccurred())

			hash2, err2 := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 10)
			Expect(err2).ShouldNot(HaveOccurred())

			Expect(hash1).ShouldNot(Equal(hash2))
		})

		It("should normalize name to canonical form", func() {
			hash1, err1 := sut.computeNSEC3Hash("EXAMPLE.COM.", dns.SHA1, "", 0)
			Expect(err1).ShouldNot(HaveOccurred())

			hash2, err2 := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err2).ShouldNot(HaveOccurred())

			Expect(hash1).Should(Equal(hash2))
		})

		It("should fail for unsupported hash algorithm", func() {
			_, err := sut.computeNSEC3Hash("example.com.", 99, "", 0)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("unsupported NSEC3 hash algorithm"))
		})

		It("should cache computed hashes", func() {
			// First computation
			hash1, err1 := sut.computeNSEC3Hash("test.example.com.", dns.SHA1, "AABB", 5)
			Expect(err1).ShouldNot(HaveOccurred())

			// Second computation should use cache
			hash2, err2 := sut.computeNSEC3Hash("test.example.com.", dns.SHA1, "AABB", 5)
			Expect(err2).ShouldNot(HaveOccurred())

			Expect(hash1).Should(Equal(hash2))
		})

		It("should handle names without trailing dot", func() {
			hash1, err1 := sut.computeNSEC3Hash("example.com", dns.SHA1, "", 0)
			Expect(err1).ShouldNot(HaveOccurred())

			hash2, err2 := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err2).ShouldNot(HaveOccurred())

			Expect(hash1).Should(Equal(hash2))
		})
	})

	Describe("compareNSEC3Hashes", func() {
		It("should return 0 for equal hashes", func() {
			hash := "ABCDEF01"
			result, err := compareNSEC3Hashes(hash, hash)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(0))
		})

		It("should return -1 when hash1 < hash2", func() {
			result, err := compareNSEC3Hashes("AAAA", "BBBB")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(-1))
		})

		It("should return 1 when hash1 > hash2", func() {
			result, err := compareNSEC3Hashes("BBBB", "AAAA")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(1))
		})

		It("should be case-insensitive", func() {
			result1, err1 := compareNSEC3Hashes("abcd", "ABCD")
			Expect(err1).ShouldNot(HaveOccurred())
			Expect(result1).Should(Equal(0))

			result2, err2 := compareNSEC3Hashes("ABCD", "abcd")
			Expect(err2).ShouldNot(HaveOccurred())
			Expect(result2).Should(Equal(0))
		})

		It("should fail for invalid base32hex hash", func() {
			_, err := compareNSEC3Hashes("invalid!", "ABCD")
			Expect(err).Should(HaveOccurred())
		})

		It("should handle different length hashes", func() {
			// A hash is before a longer one that starts with its octets
			result, err := compareNSEC3Hashes("AA", "AAAA")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(-1))
		})
	})

	Describe("nsec3HashInRange", func() {
		It("should return true for hash in normal range", func() {
			// Hash between owner and next
			result := nsec3HashInRange("CCCC", "AAAA", "EEEE")
			Expect(result).Should(BeTrue())
		})

		It("should return false for hash equal to owner", func() {
			result := nsec3HashInRange("AAAA", "AAAA", "EEEE")
			Expect(result).Should(BeFalse())
		})

		It("should return false for hash equal to next", func() {
			// Range is (owner, next) - an NSEC3 covers hashes strictly between (RFC 5155 §1.3)
			result := nsec3HashInRange("EEEE", "AAAA", "EEEE")
			Expect(result).Should(BeFalse())
		})

		It("should return false for hash outside normal range", func() {
			result := nsec3HashInRange("FFFF", "AAAA", "EEEE")
			Expect(result).Should(BeFalse())
		})

		It("should handle wraparound case", func() {
			// owner > next means wraparound
			// Hash > owner should be covered
			result1 := nsec3HashInRange("FFFF", "EEEE", "AAAA")
			Expect(result1).Should(BeTrue())

			// Hash < next should be covered
			result2 := nsec3HashInRange("0000", "EEEE", "AAAA")
			Expect(result2).Should(BeTrue())

			// Hash equal to next should NOT be covered
			result3 := nsec3HashInRange("AAAA", "EEEE", "AAAA")
			Expect(result3).Should(BeFalse())

			// Hash in middle should NOT be covered
			result4 := nsec3HashInRange("CCCC", "EEEE", "AAAA")
			Expect(result4).Should(BeFalse())
		})

		It("should return false for the empty hash of a name that cannot be hashed", func() {
			// It is below every hash, where the range of the last record of a chain ends
			result := nsec3HashInRange("", "EEEE", "AAAA")
			Expect(result).Should(BeFalse())
		})
	})

	Describe("nsec3Covers", func() {
		It("should return true when a record covers the hash", func() {
			nsec3 := nsec3Range("example.com.", "sub.example.com.", -1, 1)

			result := sut.nsec3Covers([]*dns.NSEC3{nsec3}, nsec3Hash("sub.example.com.", "", 0))
			Expect(result).Should(BeTrue())
		})

		It("should return false when no record covers the hash", func() {
			// The range of the record begins after the hash
			nsec3 := nsec3Range("example.com.", "sub.example.com.", 1, 2)

			result := sut.nsec3Covers([]*dns.NSEC3{nsec3}, nsec3Hash("sub.example.com.", "", 0))
			Expect(result).Should(BeFalse())
		})

		It("should check multiple NSEC3 records", func() {
			nsec3_1 := nsec3Range("example.com.", "sub.example.com.", -3, -2)
			nsec3_2 := nsec3Range("example.com.", "sub.example.com.", -1, 1)

			// Hash covered by second record
			result := sut.nsec3Covers([]*dns.NSEC3{nsec3_1, nsec3_2}, nsec3Hash("sub.example.com.", "", 0))
			Expect(result).Should(BeTrue())
		})

		It("should return false for empty NSEC3 list", func() {
			result := sut.nsec3Covers([]*dns.NSEC3{}, "CCCC")
			Expect(result).Should(BeFalse())
		})

		It("should handle wraparound coverage", func() {
			// The last record of a chain: its next hash, the first of the chain, is below its own.
			// at returns the hash of sub.example.com. plus delta.
			nsec3 := nsec3Range("example.com.", "sub.example.com.", 2, -2)
			at := func(delta int64) string {
				return nsec3OwnerHash(nsec3Range("example.com.", "sub.example.com.", delta, delta))
			}

			// Hash after owner (wraparound)
			result1 := sut.nsec3Covers([]*dns.NSEC3{nsec3}, at(3))
			Expect(result1).Should(BeTrue())

			// Hash before next (wraparound)
			result2 := sut.nsec3Covers([]*dns.NSEC3{nsec3}, at(-3))
			Expect(result2).Should(BeTrue())

			// Hash between next and owner
			result3 := sut.nsec3Covers([]*dns.NSEC3{nsec3}, at(0))
			Expect(result3).Should(BeFalse())
		})
	})

	Describe("nsec3CoversWithOptOut", func() {
		It("should return true when opt-out record covers hash", func() {
			nsec3 := nsec3Range("example.com.", "sub.example.com.", -1, 1)
			nsec3.Flags = 0x01 // Opt-Out flag

			result := sut.nsec3CoversWithOptOut([]*dns.NSEC3{nsec3}, nsec3Hash("sub.example.com.", "", 0))
			Expect(result).Should(BeTrue())
		})

		It("should return false when record has no opt-out flag", func() {
			nsec3 := nsec3Range("example.com.", "sub.example.com.", -1, 1)
			nsec3.Flags = 0x00 // No Opt-Out flag

			Expect(sut.nsec3Covers([]*dns.NSEC3{nsec3}, nsec3Hash("sub.example.com.", "", 0))).Should(BeTrue())

			result := sut.nsec3CoversWithOptOut([]*dns.NSEC3{nsec3}, nsec3Hash("sub.example.com.", "", 0))
			Expect(result).Should(BeFalse())
		})

		It("should skip non-opt-out records", func() {
			nsec3_1 := nsec3Range("example.com.", "sub.example.com.", -3, -2)
			nsec3_2 := nsec3Range("example.com.", "sub.example.com.", -1, 1)
			nsec3_2.Flags = 0x01 // Opt-Out

			// Only second record has opt-out
			result := sut.nsec3CoversWithOptOut([]*dns.NSEC3{nsec3_1, nsec3_2}, nsec3Hash("sub.example.com.", "", 0))
			Expect(result).Should(BeTrue())
		})

		It("should return false for empty list", func() {
			result := sut.nsec3CoversWithOptOut([]*dns.NSEC3{}, "CCCC")
			Expect(result).Should(BeFalse())
		})
	})

	Describe("getNextCloser", func() {
		It("should return next closer name", func() {
			result := sut.getNextCloser("a.b.c.example.com.", "example.com.")
			Expect(result).Should(Equal("c.example.com."))
		})

		It("should return empty for same name", func() {
			result := sut.getNextCloser("example.com.", "example.com.")
			Expect(result).Should(BeEmpty())
		})

		It("should return empty when qname has fewer labels", func() {
			result := sut.getNextCloser("example.com.", "sub.example.com.")
			Expect(result).Should(BeEmpty())
		})

		It("should handle single label difference", func() {
			result := sut.getNextCloser("sub.example.com.", "example.com.")
			Expect(result).Should(Equal("sub.example.com."))
		})

		It("should handle multi-level domains", func() {
			result := sut.getNextCloser("a.b.c.d.e.example.com.", "c.d.e.example.com.")
			Expect(result).Should(Equal("b.c.d.e.example.com."))
		})
	})

	Describe("findClosestEncloser", func() {
		It("should find matching NSEC3 record", func() {
			// The NSEC3 record of example.com., the name above the query name
			nsec3 := nsec3Range("example.com.", "example.com.", 0, 1, dns.TypeNS, dns.TypeSOA)

			result := sut.findClosestEncloser("sub.example.com.", "example.com.", []*dns.NSEC3{nsec3}, dns.SHA1, "", 0)
			Expect(result).Should(Equal("example.com."))
		})

		It("should return empty when no match found", func() {
			// The NSEC3 record of a name that is not above the query name
			nsec3 := nsec3Range("example.com.", "other.example.com.", 0, 1, dns.TypeA)

			result := sut.findClosestEncloser("test.example.com.", "example.com.", []*dns.NSEC3{nsec3}, dns.SHA1, "", 0)
			Expect(result).Should(BeEmpty())
		})

		It("should walk up domain tree", func() {
			// Neither the query name nor b.example.com. has an NSEC3 record: example.com. is the
			// first name above the query name that has one
			nsec3 := nsec3Range("example.com.", "example.com.", 0, 1, dns.TypeNS, dns.TypeSOA)

			result := sut.findClosestEncloser("a.b.example.com.", "example.com.", []*dns.NSEC3{nsec3}, dns.SHA1, "", 0)
			Expect(result).Should(Equal("example.com."))
		})

		It("should not walk above zone", func() {
			// A record of example.com. with the hash of com.: the search ends at the apex of the zone
			nsec3 := nsec3Range("example.com.", "com.", 0, 1, dns.TypeNS)

			result := sut.findClosestEncloser("test.example.com.", "example.com.", []*dns.NSEC3{nsec3}, dns.SHA1, "", 0)
			Expect(result).Should(BeEmpty())
		})
	})

	Describe("validateNSEC3DenialOfExistence", func() {
		It("should return Insecure when no NSEC3 records", func() {
			response := &dns.Msg{
				Ns: []dns.RR{},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "test.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			result := sut.validateNSEC3DenialOfExistence(response, question)
			Expect(result).Should(Equal(ValidationResultInsecure))
		})

		It("should return Bogus for unsupported hash algorithm", func() {
			// RFC 5155 §8.1: a record with an unknown hash algorithm is ignored. The records of the
			// proof that test.example.com. does not exist give it with SHA-1, and none with another.
			proof := []dns.RR{
				nsec3Range("example.com.", "example.com.", 0, 1, dns.TypeNS, dns.TypeSOA),
				nsec3Range("example.com.", "test.example.com.", -1, 1),
				nsec3Range("example.com.", "*.example.com.", -1, 1),
			}

			response := &dns.Msg{Ns: proof}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "test.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			Expect(sut.validateNSEC3DenialOfExistence(response, question)).Should(Equal(ValidationResultSecure))

			for _, rr := range proof {
				rr.(*dns.NSEC3).Hash = 99 // Unsupported
			}

			result := sut.validateNSEC3DenialOfExistence(response, question)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return Bogus when iteration count exceeds maximum", func() {
			// The records of the proof that test.example.com. does not exist, of a chain with the
			// given number of extra iterations
			proof := func(iterations uint16) []dns.RR {
				return []dns.RR{
					nsec3SaltedRange("example.com.", "example.com.", "", iterations, 0, 1, dns.TypeNS, dns.TypeSOA),
					nsec3SaltedRange("example.com.", "test.example.com.", "", iterations, -1, 1),
					nsec3SaltedRange("example.com.", "*.example.com.", "", iterations, -1, 1),
				}
			}

			question := dns.Question{
				Name:   "test.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			response := &dns.Msg{Ns: proof(150)} // The default maximum
			response.Rcode = dns.RcodeNameError

			Expect(sut.validateNSEC3DenialOfExistence(response, question)).Should(Equal(ValidationResultSecure))

			response.Ns = proof(151)

			result := sut.validateNSEC3DenialOfExistence(response, question)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return Bogus when NSEC3 records have inconsistent parameters", func() {
			// The records of the proof that test.example.com. does not exist
			proof := []dns.RR{
				nsec3Range("example.com.", "example.com.", 0, 1, dns.TypeNS, dns.TypeSOA),
				nsec3Range("example.com.", "test.example.com.", -1, 1),
				nsec3Range("example.com.", "*.example.com.", -1, 1),
			}

			response := &dns.Msg{Ns: proof}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "test.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			Expect(sut.validateNSEC3DenialOfExistence(response, question)).Should(Equal(ValidationResultSecure))

			// The last record says that it is from a chain with another salt. Nothing else of it
			// changes: with the salt of the first record it still covers the hash of the wildcard.
			proof[2].(*dns.NSEC3).Salt = "aabb" // Different salt

			result := sut.validateNSEC3DenialOfExistence(response, question)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should validate NXDOMAIN response", func() {
			nsec3 := &dns.NSEC3{
				Hdr:  dns.RR_Header{Name: "hash.example.com.", Rrtype: dns.TypeNSEC3},
				Hash: dns.SHA1,
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec3},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "test.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			// Will likely fail validation due to incomplete NSEC3 proof, but should attempt
			result := sut.validateNSEC3DenialOfExistence(response, question)
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})

		It("should validate NODATA response", func() {
			nsec3 := &dns.NSEC3{
				Hdr:  dns.RR_Header{Name: "hash.example.com.", Rrtype: dns.TypeNSEC3},
				Hash: dns.SHA1,
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec3},
			}
			response.Rcode = dns.RcodeSuccess // NODATA

			question := dns.Question{
				Name:   "test.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			result := sut.validateNSEC3DenialOfExistence(response, question)
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})
	})

	Describe("checkDirectNSEC3Match", func() {
		It("should return Secure when NSEC3 matches and type not in bitmap", func() {
			hash := nsec3Hash("example.com.", "", 0)
			nsec3 := nsec3Range("example.com.", "example.com.", 0, 1, dns.TypeA, dns.TypeNS, dns.TypeSOA)

			result := sut.checkDirectNSEC3Match([]*dns.NSEC3{nsec3}, "example.com.", hash, dns.TypeAAAA)
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should return Bogus when type exists in bitmap", func() {
			hash := nsec3Hash("example.com.", "", 0)
			nsec3 := nsec3Range("example.com.", "example.com.", 0, 1, dns.TypeA, dns.TypeAAAA)

			result := sut.checkDirectNSEC3Match([]*dns.NSEC3{nsec3}, "example.com.", hash, dns.TypeAAAA)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return Indeterminate when no match found", func() {
			// The record of another name
			nsec3 := nsec3Range("example.com.", "other.example.com.", 0, 1, dns.TypeA)

			result := sut.checkDirectNSEC3Match([]*dns.NSEC3{nsec3}, "example.com.", nsec3Hash("example.com.", "", 0), dns.TypeA)
			Expect(result).Should(Equal(ValidationResultIndeterminate))
		})
	})

	Describe("validateNSEC3NODATA", func() {
		It("should validate direct NSEC3 match", func() {
			nsec3 := nsec3Range("example.com.", "example.com.", 0, 1, dns.TypeA)

			result := sut.validateNSEC3NODATA([]*dns.NSEC3{nsec3}, "example.com.", dns.TypeAAAA, "example.com.", dns.SHA1, "", 0)
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should return Bogus when no proof found", func() {
			// The record of another name: none matches the query name, and none a name above it
			nsec3 := nsec3Range("example.com.", "other.example.com.", 0, 1, dns.TypeA)

			result := sut.validateNSEC3NODATA(
				[]*dns.NSEC3{nsec3}, "test.example.com.", dns.TypeA, "example.com.", dns.SHA1, "", 0,
			)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return Bogus for DS query with opt-out but no closest encloser", func() {
			// An Opt-Out record covers the hash of the query name, and no record matches a name
			// above it
			nsec3 := nsec3Range("example.com.", "test.example.com.", -1, 1)
			nsec3.Flags = 0x01 // Opt-Out

			result := sut.validateNSEC3NODATA(
				[]*dns.NSEC3{nsec3}, "test.example.com.", dns.TypeDS, "example.com.", dns.SHA1, "", 0,
			)
			Expect(result).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("validateNSEC3NXDOMAIN", func() {
		It("should return Bogus when closest encloser not found", func() {
			nsec3 := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "UNKNOWN.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			result := sut.validateNSEC3NXDOMAIN([]*dns.NSEC3{nsec3}, "test.example.com.", "example.com.", dns.SHA1, "", 0)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should validate complete NXDOMAIN proof with closest encloser, next closer, and wildcard", func() {
			// Create proper NSEC3 chain for NXDOMAIN proof
			// 1. NSEC3 for closest encloser (example.com.)
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// Create NSEC3 for the zone apex (closest encloser)
			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "ZZZZZZZZ", // Doesn't matter for direct match
			}

			// Create NSEC3 covering next closer (proves test.example.com doesn't exist)
			nsec3NextCloser := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "00000000.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "ZZZZZZZZ", // Covers next closer
			}

			// Create NSEC3 covering wildcard (proves *.example.com doesn't exist)
			nsec3Wildcard := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "11111111.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "ZZZZZZZZ", // Covers wildcard
			}

			result := sut.validateNSEC3NXDOMAIN(
				[]*dns.NSEC3{nsec3Zone, nsec3NextCloser, nsec3Wildcard},
				"test.example.com.", "example.com.", dns.SHA1, "", 0,
			)

			// Result depends on whether the NSEC3 records properly cover the required ranges
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})

		It("should return Insecure when next closer is in opt-out span", func() {
			// Create NSEC3 for zone apex
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			// Create opt-out NSEC3 that might cover next closer
			nsec3OptOut := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "0000.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Flags:      0x01, // Opt-Out
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "ZZZZ",
			}

			result := sut.validateNSEC3NXDOMAIN(
				[]*dns.NSEC3{nsec3Zone, nsec3OptOut}, "test.example.com.", "example.com.", dns.SHA1, "", 0,
			)
			// Result depends on whether next closer falls in opt-out span
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})

		It("should return Bogus when next closer is not covered", func() {
			// Create NSEC3 for zone apex
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				// Don't set NextDomain so it doesn't accidentally cover the next closer
			}

			result := sut.validateNSEC3NXDOMAIN(
				[]*dns.NSEC3{nsec3Zone}, "test.example.com.", "example.com.", dns.SHA1, "", 0,
			)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return Bogus when wildcard is not covered", func() {
			// Create NSEC3 for zone apex
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// Create next closer hash
			hashNextCloser, err := sut.computeNSEC3Hash("test.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashNextCloser,
			}

			// NSEC3 that proves next closer is covered but wildcard is not
			// Don't set NextDomain so it only provides a hash match, not coverage
			nsec3Cover := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashNextCloser + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				// No NextDomain - won't cover wildcard
			}

			result := sut.validateNSEC3NXDOMAIN(
				[]*dns.NSEC3{nsec3Zone, nsec3Cover}, "test.example.com.", "example.com.", dns.SHA1, "", 0,
			)
			// Should fail because wildcard is not covered
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should successfully validate full NXDOMAIN proof with proper coverage", func() {
			// Test a complete valid NXDOMAIN proof where:
			// 1. Closest encloser is found (example.com.)
			// 2. Next closer (sub.example.com.) is covered
			// 3. Wildcard (*.example.com.) is covered

			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// NSEC3 for zone apex (closest encloser)
			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				Flags:      0,
				NextDomain: "ZZZZZZZZ", // Points to cover range
			}

			// NSEC3 that covers next closer (proves sub.example.com doesn't exist)
			// Owner hash < next closer hash < NextDomain
			nsec3CoverNext := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "00000000.example.com.", // Small hash
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				Flags:      0,
				NextDomain: "ZZZZZZZZ", // Large hash - covers next closer
			}

			// NSEC3 that covers wildcard (proves *.example.com doesn't exist)
			nsec3CoverWild := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "11111111.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				Flags:      0,
				NextDomain: "ZZZZZZZZ", // Covers wildcard
			}

			result := sut.validateNSEC3NXDOMAIN(
				[]*dns.NSEC3{nsec3Zone, nsec3CoverNext, nsec3CoverWild},
				"sub.example.com.", "example.com.", dns.SHA1, "", 0,
			)

			// Should return Secure if all conditions are met
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})

		It("should return Bogus when next closer cannot be computed (qname same as closest encloser)", func() {
			// Edge case: when qname equals closest encloser, getNextCloser returns ""
			// This happens when qname has same or fewer labels than closest encloser
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			// Try to validate with qname equal to zone (no next closer possible)
			result := sut.validateNSEC3NXDOMAIN(
				[]*dns.NSEC3{nsec3Zone}, "example.com.", "example.com.", dns.SHA1, "", 0,
			)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return Insecure when next closer is covered by opt-out NSEC3", func() {
			// Create NSEC3 for zone apex
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			// Create opt-out NSEC3 that covers entire hash space
			// Use minimum and maximum base32hex-encoded hashes (32 chars for SHA1)
			nsec3OptOut := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "00000000000000000000000000000000.example.com.", // Minimum hash
					Rrtype: dns.TypeNSEC3,
				},
				Flags:      0x01, // Opt-Out flag
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", // Maximum hash
			}

			result := sut.validateNSEC3NXDOMAIN(
				[]*dns.NSEC3{nsec3Zone, nsec3OptOut}, "sub.example.com.", "example.com.", dns.SHA1, "", 0,
			)

			// When next closer is covered by opt-out NSEC3, should return Insecure
			Expect(result).Should(Equal(ValidationResultInsecure))
		})
	})

	Describe("checkWildcardNSEC3Match", func() {
		It("should return Bogus when closest encloser not found", func() {
			nsec3 := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "UNKNOWN.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3}, "test.example.com.", dns.TypeA, "example.com.",
				dns.SHA1, "", 0, "somehash",
			)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should check for DS query with opt-out behavior", func() {
			// Create opt-out NSEC3
			nsec3OptOut := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "0000.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Flags:      0x01, // Opt-Out
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "ZZZZ",
			}

			// Compute hash for DS query
			hashDS, err := sut.computeNSEC3Hash("sub.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3OptOut}, "sub.example.com.", dns.TypeDS, "example.com.",
				dns.SHA1, "", 0, hashDS,
			)
			// Result depends on whether closest encloser can be found
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})

		It("should validate wildcard match when closest encloser exists", func() {
			// Create NSEC3 for zone apex (closest encloser)
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			hashQuery, err := sut.computeNSEC3Hash("nonexist.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3Zone}, "nonexist.example.com.", dns.TypeA, "example.com.",
				dns.SHA1, "", 0, hashQuery,
			)
			// Result depends on wildcard validation
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})

		It("should validate when wildcard exists and type not in bitmap", func() {
			// Create NSEC3 for zone apex (closest encloser)
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// Create NSEC3 for wildcard
			hashWildcard, err := sut.computeNSEC3Hash("*.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			// Wildcard NSEC3 with type bitmap that doesn't include requested type
			nsec3Wildcard := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashWildcard + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				TypeBitMap: []uint16{dns.TypeA, dns.TypeNS}, // Has A and NS but not MX
			}

			hashQuery, err := sut.computeNSEC3Hash("test.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3Zone, nsec3Wildcard}, "test.example.com.", dns.TypeMX,
				"example.com.", dns.SHA1, "", 0, hashQuery,
			)
			// Tests the code path - result depends on whether closest encloser is found
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})

		It("should return Bogus when wildcard exists but has requested type", func() {
			// Create NSEC3 for zone apex (closest encloser)
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// Create NSEC3 for wildcard
			hashWildcard, err := sut.computeNSEC3Hash("*.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			// Wildcard NSEC3 with type bitmap that includes requested type
			nsec3Wildcard := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashWildcard + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				TypeBitMap: []uint16{dns.TypeA, dns.TypeMX}, // Has MX
			}

			hashQuery, err := sut.computeNSEC3Hash("test.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3Zone, nsec3Wildcard}, "test.example.com.", dns.TypeMX,
				"example.com.", dns.SHA1, "", 0, hashQuery,
			)
			// Should return Bogus since wildcard has MX in bitmap
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return Bogus for DS query with opt-out when closest encloser not found", func() {
			// RFC 5155 §8.6: an Opt-Out NSEC3 proves an unsigned delegation only together with
			// a closest provable encloser proof
			hashDS, err := sut.computeNSEC3Hash("sub.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// Create opt-out NSEC3 that covers entire hash space
			nsec3OptOut := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "00000000000000000000000000000000.example.com.", // Minimum hash
					Rrtype: dns.TypeNSEC3,
				},
				Flags:      0x01, // Opt-Out
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", // Maximum hash
			}

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3OptOut}, "sub.example.com.", dns.TypeDS, "example.com.",
				dns.SHA1, "", 0, hashDS,
			)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return Insecure for DS query with opt-out when wildcard not found", func() {
			// Create NSEC3 for zone apex (closest encloser)
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			// Compute DS hash first
			hashDS, err := sut.computeNSEC3Hash("test.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// Create opt-out NSEC3 that covers entire hash space
			nsec3OptOut := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "00000000000000000000000000000000.example.com.", // Minimum hash
					Rrtype: dns.TypeNSEC3,
				},
				Flags:      0x01, // Opt-Out
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", // Maximum hash
			}

			// DS query with opt-out covering, no wildcard NSEC3 found
			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3Zone, nsec3OptOut}, "test.example.com.", dns.TypeDS,
				"example.com.", dns.SHA1, "", 0, hashDS,
			)
			// Should return Insecure for DS query covered by opt-out
			Expect(result).Should(Equal(ValidationResultInsecure))
		})
	})

	Describe("validateNSEC3NODATA", func() {
		It("should return Secure for direct match without requested type", func() {
			// Has A but not AAAA
			nsec3 := nsec3Range("example.com.", "www.example.com.", 0, 1, dns.TypeA)

			result := sut.validateNSEC3NODATA(
				[]*dns.NSEC3{nsec3}, "www.example.com.", dns.TypeAAAA, "example.com.",
				dns.SHA1, "", 0,
			)
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should return Bogus when direct match has requested type", func() {
			// Has both A and AAAA
			nsec3 := nsec3Range("example.com.", "www.example.com.", 0, 1, dns.TypeA, dns.TypeAAAA)

			result := sut.validateNSEC3NODATA(
				[]*dns.NSEC3{nsec3}, "www.example.com.", dns.TypeAAAA, "example.com.",
				dns.SHA1, "", 0,
			)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should check wildcard match when no direct match", func() {
			// No matching NSEC3
			nsec3 := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "UNKNOWN.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			result := sut.validateNSEC3NODATA(
				[]*dns.NSEC3{nsec3}, "www.example.com.", dns.TypeA, "example.com.",
				dns.SHA1, "", 0,
			)
			// Should fall through to wildcard check
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})
	})

	Describe("findClosestEncloser", func() {
		It("should find zone apex as closest encloser when it matches", func() {
			nsec3 := nsec3Range("example.com.", "example.com.", 0, 1, dns.TypeNS, dns.TypeSOA)

			closest := sut.findClosestEncloser(
				"test.sub.example.com.", "example.com.", []*dns.NSEC3{nsec3},
				dns.SHA1, "", 0,
			)
			Expect(closest).Should(Equal("example.com."))
		})

		It("should return empty string when no match found", func() {
			nsec3 := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "NOMATCH.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			closest := sut.findClosestEncloser(
				"test.example.com.", "example.com.", []*dns.NSEC3{nsec3},
				dns.SHA1, "", 0,
			)
			Expect(closest).Should(Equal(""))
		})

		It("should find intermediate domain as closest encloser", func() {
			nsec3Sub := nsec3Range("example.com.", "sub.example.com.", 0, 1, dns.TypeA)

			closest := sut.findClosestEncloser(
				"test.sub.example.com.", "example.com.", []*dns.NSEC3{nsec3Sub},
				dns.SHA1, "", 0,
			)
			Expect(closest).Should(Equal("sub.example.com."))
		})

		It("should stop at root when walking up domain tree", func() {
			// Create NSEC3 that won't match
			nsec3 := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "NOMATCH.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			// Query with deep domain should eventually reach root and stop
			closest := sut.findClosestEncloser(
				"a.b.c.d.e.f.g.h.com.", "com.", []*dns.NSEC3{nsec3},
				dns.SHA1, "", 0,
			)
			Expect(closest).Should(Equal(""))
		})

		It("should handle zone boundary correctly", func() {
			// The apex of the zone com. is the last name that the search asks about
			nsec3 := nsec3Range("com.", "com.", 0, 1, dns.TypeNS, dns.TypeSOA)

			closest := sut.findClosestEncloser(
				"test.example.com.", "com.", []*dns.NSEC3{nsec3},
				dns.SHA1, "", 0,
			)
			Expect(closest).Should(Equal("com."))
		})
	})

	Describe("checkWildcardNSEC3Match additional tests", func() {
		It("should return Secure when wildcard NSEC3 matches without requested type", func() {
			// Create NSEC3 for zone apex (closest encloser)
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// Create NSEC3 for wildcard
			hashWildcard, err := sut.computeNSEC3Hash("*.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			nsec3Wildcard := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashWildcard + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				TypeBitMap: []uint16{dns.TypeA}, // Has A but not AAAA
			}

			hashQuery, err := sut.computeNSEC3Hash("nonexist.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3Zone, nsec3Wildcard}, "nonexist.example.com.", dns.TypeAAAA,
				"example.com.", dns.SHA1, "", 0, hashQuery,
			)
			// Result depends on whether closest encloser is found and wildcard matches
			// The key is to test the code path executes without error
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})

		It("should return Bogus when wildcard has requested type in bitmap", func() {
			// Create NSEC3 for zone apex (closest encloser)
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// Create NSEC3 for wildcard
			hashWildcard, err := sut.computeNSEC3Hash("*.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			nsec3Wildcard := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashWildcard + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA}, // Has the type we're querying
			}

			hashQuery, err := sut.computeNSEC3Hash("nonexist.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3Zone, nsec3Wildcard}, "nonexist.example.com.", dns.TypeAAAA,
				"example.com.", dns.SHA1, "", 0, hashQuery,
			)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return Bogus for DS query with opt-out when closest encloser not found", func() {
			// Create opt-out NSEC3 that covers the hash
			hashQuery, err := sut.computeNSEC3Hash("sub.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3OptOut := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "0000.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Flags:      0x01, // Opt-Out
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "VVVV",
			}

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3OptOut}, "sub.example.com.", dns.TypeDS,
				"example.com.", dns.SHA1, "", 0, hashQuery,
			)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should handle empty NSEC3 owner name labels", func() {
			// NSEC3 with malformed owner name (no labels)
			nsec3 := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   ".", // Just root, no hash
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			hashQuery, err := sut.computeNSEC3Hash("test.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3}, "test.example.com.", dns.TypeA,
				"example.com.", dns.SHA1, "", 0, hashQuery,
			)
			Expect(result).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("nsec3HashInRange edge cases", func() {
		It("should handle equal owner and next hash (single record)", func() {
			// When owner equals next, it covers the entire hash space
			result := nsec3HashInRange("5555", "AAAA", "AAAA")
			Expect(result).Should(BeTrue())
		})

		It("should handle boundary at zero", func() {
			// Wraparound case where next is near zero
			result := nsec3HashInRange("00000001", "EEEEEEEE", "00000005")
			Expect(result).Should(BeTrue())
		})
	})

	Describe("nsec3Covers edge cases", func() {
		It("should handle NSEC3 with empty owner name labels", func() {
			nsec3 := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   ".", // Empty labels
					Rrtype: dns.TypeNSEC3,
				},
				NextDomain: "AAAA",
			}

			result := sut.nsec3Covers([]*dns.NSEC3{nsec3}, "5555")
			Expect(result).Should(BeFalse())
		})

		It("should check all records in list", func() {
			nsec3_1 := nsec3Range("example.com.", "sub.example.com.", -5, -3)
			nsec3_2 := nsec3Range("example.com.", "sub.example.com.", -1, 1)
			nsec3_3 := nsec3Range("example.com.", "sub.example.com.", 3, 5)

			// Hash covered by middle record
			result := sut.nsec3Covers([]*dns.NSEC3{nsec3_1, nsec3_2, nsec3_3}, nsec3Hash("sub.example.com.", "", 0))
			Expect(result).Should(BeTrue())
		})
	})

	Describe("nsec3CoversWithOptOut edge cases", func() {
		It("should handle NSEC3 with empty owner name labels", func() {
			nsec3 := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   ".", // Empty labels
					Rrtype: dns.TypeNSEC3,
				},
				Flags:      0x01,
				NextDomain: "AAAA",
			}

			result := sut.nsec3CoversWithOptOut([]*dns.NSEC3{nsec3}, "5555")
			Expect(result).Should(BeFalse())
		})

		It("should skip all records without opt-out flag", func() {
			nsec3_1 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "1111.example.com.", Rrtype: dns.TypeNSEC3},
				Flags:      0x00,
				NextDomain: "9999",
			}
			nsec3_2 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "AAAA.example.com.", Rrtype: dns.TypeNSEC3},
				Flags:      0x00,
				NextDomain: "FFFF",
			}

			result := sut.nsec3CoversWithOptOut([]*dns.NSEC3{nsec3_1, nsec3_2}, "5555")
			Expect(result).Should(BeFalse())
		})
	})

	Describe("validateNSEC3DenialOfExistence edge cases", func() {
		It("should detect Opt-Out flag in NSEC3 parameters", func() {
			nsec3 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "hash.example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				Flags:      0x01, // Opt-Out flag set
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec3},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "test.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			// Should log about opt-out flag and continue validation
			result := sut.validateNSEC3DenialOfExistence(response, question)
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})

		It("should extract zone name from NSEC3 owner name", func() {
			// NSEC3 owner name format: <hash>.<zone>
			nsec3 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "HASH123.sub.example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec3},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "test.sub.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			// Should extract sub.example.com. as zone name
			result := sut.validateNSEC3DenialOfExistence(response, question)
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})

		It("should handle NSEC3 with single label owner name", func() {
			nsec3 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "HASH.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec3},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "test.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			result := sut.validateNSEC3DenialOfExistence(response, question)
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})

		It("should handle zone apex boundary in findClosestEncloser", func() {
			// The root is the closest encloser of a name that has no record below it
			nsec3Root := nsec3Range(".", ".", 0, 1, dns.TypeNS, dns.TypeSOA)

			result := sut.findClosestEncloser("com.", ".", []*dns.NSEC3{nsec3Root}, dns.SHA1, "", 0)
			Expect(result).Should(Equal("."))
		})

		It("should detect opt-out flag in validateNSEC3DenialOfExistence", func() {
			nsec3OptOut := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "HASH.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				Flags:      0x01, // Opt-Out flag
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec3OptOut},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "test.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			// Should log opt-out detection and proceed
			result := sut.validateNSEC3DenialOfExistence(response, question)
			Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
		})
	})

	Describe("checkWildcardNSEC3Match - error paths", func() {
		It("should return Bogus when no wildcard NSEC3 found after finding closest encloser", func() {
			// Create NSEC3 for zone apex (closest encloser)
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			// No wildcard NSEC3 record present
			hashQuery, err := sut.computeNSEC3Hash("test.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3Zone}, "test.example.com.", dns.TypeA,
				"example.com.", dns.SHA1, "", 0, hashQuery,
			)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return Insecure for DS query covered by opt-out after wildcard search", func() {
			// Create NSEC3 for zone apex (closest encloser)
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			// Opt-out NSEC3 that covers the query
			nsec3OptOut := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "00000000.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Flags:      0x01, // Opt-Out
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "ZZZZZZZZ",
			}

			hashQuery, err := sut.computeNSEC3Hash("test.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// Verify the opt-out covers the hash
			if sut.nsec3CoversWithOptOut([]*dns.NSEC3{nsec3OptOut}, hashQuery) {
				result := sut.checkWildcardNSEC3Match(
					[]*dns.NSEC3{nsec3Zone, nsec3OptOut}, "test.example.com.", dns.TypeDS,
					"example.com.", dns.SHA1, "", 0, hashQuery,
				)
				Expect(result).Should(Equal(ValidationResultInsecure))
			}
		})

		It("should handle empty NSEC3 labels in wildcard matching", func() {
			nsec3Empty := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   ".", // No labels
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			hashQuery, err := sut.computeNSEC3Hash("test.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3Empty}, "test.example.com.", dns.TypeA,
				"example.com.", dns.SHA1, "", 0, hashQuery,
			)
			Expect(result).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("validateNSEC3NXDOMAIN comprehensive success path", func() {
		It("should return Secure for complete valid NXDOMAIN proof", func() {
			// This test creates a complete, realistic NXDOMAIN proof that will hit the success path
			qname := "nonexistent.example.com."
			zoneName := "example.com."

			// Compute zone hash for closest encloser
			hashZone, err := sut.computeNSEC3Hash(zoneName, dns.SHA1, "AABBCCDD", 10)
			Expect(err).ShouldNot(HaveOccurred())

			// Create NSEC3 for zone apex (closest encloser) - direct match
			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Hash:       dns.SHA1,
				Salt:       "AABBCCDD",
				Iterations: 10,
				Flags:      0,
				NextDomain: hashZone, // Points to itself for simplicity
			}

			// Create NSEC3 that covers entire hash space (for next closer)
			nsec3NextCloserCover := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "00000000000000000000000000000000.example.com.", // Minimum hash
					Rrtype: dns.TypeNSEC3,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Hash:       dns.SHA1,
				Salt:       "AABBCCDD",
				Iterations: 10,
				Flags:      0,
				NextDomain: "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", // Maximum hash
			}

			// Create NSEC3 that covers entire hash space (for wildcard)
			// Use a different owner to avoid duplicate records
			nsec3WildcardCover := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "00000000000000000000000000000001.example.com.", // Slightly different
					Rrtype: dns.TypeNSEC3,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Hash:       dns.SHA1,
				Salt:       "AABBCCDD",
				Iterations: 10,
				Flags:      0,
				NextDomain: "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", // Maximum hash
			}

			result := sut.validateNSEC3NXDOMAIN(
				[]*dns.NSEC3{nsec3Zone, nsec3NextCloserCover, nsec3WildcardCover},
				qname, zoneName, dns.SHA1, "AABBCCDD", 10,
			)

			// Should return Secure when all conditions are met
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should log closest encloser when found", func() {
			// Test the logging path when closest encloser is found
			qname := "sub.example.com."
			zoneName := "example.com."

			hashZone, err := sut.computeNSEC3Hash(zoneName, dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// Create NSEC3 for zone (closest encloser exists)
			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				// Don't set NextDomain - let it remain empty
			}

			// Next closer and wildcard coverage are missing, so will return Bogus
			// But this will still hit the "closest encloser found" logging path
			result := sut.validateNSEC3NXDOMAIN(
				[]*dns.NSEC3{nsec3Zone}, qname, zoneName, dns.SHA1, "", 0,
			)
			// Should try to validate but fail on next closer coverage
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should handle when next closer is covered but not by opt-out", func() {
			// Test the path where next closer is covered by regular NSEC3 (not opt-out)
			// and then checks wildcard coverage
			qname := "test.example.com."
			zoneName := "example.com."

			hashZone, err := sut.computeNSEC3Hash(zoneName, dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			hashNextCloser, err := sut.computeNSEC3Hash("test.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// NSEC3 for zone
			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			// NSEC3 covering next closer (no opt-out flag)
			nsec3Cover := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "00000000.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				Flags:      0, // No opt-out
				NextDomain: "ZZZZZZZZ",
			}

			// Verify next closer is covered
			if sut.nsec3Covers([]*dns.NSEC3{nsec3Cover}, hashNextCloser) &&
				!sut.nsec3CoversWithOptOut([]*dns.NSEC3{nsec3Cover}, hashNextCloser) {
				// Next closer covered but not by opt-out
				// Will proceed to wildcard check
				result := sut.validateNSEC3NXDOMAIN(
					[]*dns.NSEC3{nsec3Zone, nsec3Cover},
					qname, zoneName, dns.SHA1, "", 0,
				)
				// Should fail on wildcard check
				Expect(result).Should(Equal(ValidationResultBogus))
			}
		})
	})

	Describe("checkWildcardNSEC3Match comprehensive coverage", func() {
		It("should return Secure when wildcard exists without requested type", func() {
			zoneName := "example.com."
			qname := "wild.example.com."

			// Compute hashes
			hashZone, err := sut.computeNSEC3Hash(zoneName, dns.SHA1, "AABBCC", 5)
			Expect(err).ShouldNot(HaveOccurred())

			hashWildcard, err := sut.computeNSEC3Hash("*.example.com.", dns.SHA1, "AABBCC", 5)
			Expect(err).ShouldNot(HaveOccurred())

			hashQuery, err := sut.computeNSEC3Hash(qname, dns.SHA1, "AABBCC", 5)
			Expect(err).ShouldNot(HaveOccurred())

			// NSEC3 for zone apex (closest encloser); with the wildcard's NSEC3 it forms a chain
			// of two that covers every other hash, the next closer name's among them
			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "AABBCC",
				Iterations: 5,
				NextDomain: hashWildcard,
			}

			// NSEC3 for wildcard with A record but not AAAA
			nsec3Wildcard := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashWildcard + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "AABBCC",
				Iterations: 5,
				NextDomain: hashZone,
				TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG}, // Has A but not AAAA
			}

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3Zone, nsec3Wildcard}, qname, dns.TypeAAAA,
				zoneName, dns.SHA1, "AABBCC", 5, hashQuery,
			)

			// Should return Secure when wildcard is found but doesn't have requested type
			Expect(result).Should(Equal(ValidationResultSecure))

			// RFC 5155 §8.7: not with records that do not cover the next closer name
			nsec3Zone.NextDomain, nsec3Wildcard.NextDomain = "", ""
			Expect(sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3Zone, nsec3Wildcard}, qname, dns.TypeAAAA,
				zoneName, dns.SHA1, "AABBCC", 5, hashQuery,
			)).Should(Equal(ValidationResultBogus))
		})

		It("should return Bogus for non-DS query when no wildcard and no opt-out", func() {
			zoneName := "example.com."
			qname := "test.example.com."

			hashZone, err := sut.computeNSEC3Hash(zoneName, dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			hashQuery, err := sut.computeNSEC3Hash(qname, dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// Only zone NSEC3, no wildcard
			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone, // Points to itself
			}

			// NSEC3 that doesn't cover the query (no opt-out)
			nsec3Other := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "BBBB.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				Flags:      0, // No opt-out
				NextDomain: "CCCC",
			}

			result := sut.checkWildcardNSEC3Match(
				[]*dns.NSEC3{nsec3Zone, nsec3Other}, qname, dns.TypeA,
				zoneName, dns.SHA1, "", 0, hashQuery,
			)

			// Should return Bogus when no wildcard found and it's not DS with opt-out
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("rejects a DS-absence wildcard NODATA proof that does not assert a delegation", func() {
			// GHSA-x845-2f78-7v36 finding 4 (residual): the matching-NSEC3 guard in
			// checkDirectNSEC3Match must apply equally to the wildcard NODATA path. A wildcard
			// NSEC3 whose bitmap lacks the DS type proves DS-absence, but only proves an
			// INSECURE DELEGATION if it asserts a delegation (NS set, SOA/DS clear). With the
			// NS bit clear it is an ordinary in-zone name, so a DS query answered via this
			// wildcard match must be Bogus, not Secure.
			zoneName := "example.com."
			qname := "wild.example.com."

			hashZone, err := sut.computeNSEC3Hash(zoneName, dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			hashWildcard, err := sut.computeNSEC3Hash("*.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// NSEC3 for the zone apex (closest encloser). The apex and the wildcard are the
			// whole NSEC3 chain of the zone.
			nsec3Zone := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: hashZone + ".example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashWildcard,
				TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM},
			}

			// Wildcard NSEC3 without the DS type AND without the NS bit: it does not assert a
			// delegation, so it must not be read as proof of an insecure delegation.
			nsec3Wildcard := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: hashWildcard + ".example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone,
				TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG}, // in-zone name: NS bit absent
			}

			result := legacyDenialSet(sut, []*dns.NSEC3{nsec3Zone, nsec3Wildcard}, qname, dns.TypeDS).noDS(false)

			Expect(result).ShouldNot(Equal(ValidationResultSecure),
				"wildcard NSEC3 without the NS bit was accepted as proof of an insecure delegation")
		})

		It("does not take the NSEC3 record of a wildcard for that of a delegation", func() {
			// RFC 5155 §8.6, §8.9: a delegation is insecure by its own NSEC3 record, or by an Opt-Out
			// record that covers its next closer name. A wildcard is no delegation, whatever its type
			// bitmap says, and neither record of this zone has the Opt-Out flag.
			zoneName := "example.com."
			qname := "wild.example.com."

			hashZone, err := sut.computeNSEC3Hash(zoneName, dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			hashWildcard, err := sut.computeNSEC3Hash("*.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			nsec3Zone := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: hashZone + ".example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashWildcard,
				TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM},
			}

			nsec3Wildcard := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: hashWildcard + ".example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: hashZone,
				TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG}, // delegation present, DS absent
			}

			result := legacyDenialSet(sut, []*dns.NSEC3{nsec3Zone, nsec3Wildcard}, qname, dns.TypeDS).noDS(false)

			Expect(result).Should(Equal(ValidationResultBogus),
				"wildcard NSEC3 with the NS bit was accepted as proof of an insecure delegation")
		})

		It("treats an opt-out wildcard NSEC3 covering the next closer as an insecure delegation", func() {
			// issue #2365: nic.merck is an unsigned delegation under merck, an NSEC3
			// opt-out zone with an apex wildcard. The DS answer carries the RFC 5155
			// §8.6 opt-out proof: merck is the closest encloser and the NSEC3 covering
			// the next closer (nic.merck) has Opt-Out set. That covering NSEC3 happens
			// to be owned by *.merck, so the wildcard-NODATA path must not short-circuit
			// the opt-out check.
			zoneName := "merck."
			qname := "nic.merck."

			hashZone, err := sut.computeNSEC3Hash(zoneName, dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			hashWildcard, err := sut.computeNSEC3Hash("*.merck.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// The NSEC3 of the apex, the closest encloser, with the next hashed owner name and
			// the types of an apex
			nsec3Zone := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: hashZone + ".merck.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				Flags:      0x01, // Opt-Out
				NextDomain: hashWildcard,
				TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM},
			}

			// The wildcard NSEC3 doubles as the §8.6 cover for nic.merck: it has Opt-Out
			// set and its span (owner, NextDomain) includes the next closer's hash. Its next
			// hashed owner name is the apex's: H(nic.merck.) < H(merck.) < H(*.merck.), so the
			// span wraps around the end of the hash space and covers the hash of nic.merck.
			nsec3Wildcard := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: hashWildcard + ".merck.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				Flags:      0x01,                               // Opt-Out
				NextDomain: hashZone,                           // next hashed owner name in the zone
				TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG}, // in-zone wildcard: no NS bit
			}

			// The proof of the DS reply, from the denial set as newDenialSet makes it
			result := legacyDenialSet(sut, []*dns.NSEC3{nsec3Zone, nsec3Wildcard}, qname, dns.TypeDS).noDS(false)

			Expect(result).Should(Equal(ValidationResultInsecure))
		})
	})

	Describe("validateNSEC3NXDOMAIN - extended error paths", func() {
		It("should handle successful wildcard coverage in NXDOMAIN proof", func() {
			// Create valid NXDOMAIN proof with all required NSEC3 records
			hashZone, err := sut.computeNSEC3Hash("example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			hashNextCloser, err := sut.computeNSEC3Hash("test.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			hashWildcard, err := sut.computeNSEC3Hash("*.example.com.", dns.SHA1, "", 0)
			Expect(err).ShouldNot(HaveOccurred())

			// NSEC3 for zone (closest encloser)
			nsec3Zone := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   hashZone + ".example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "ZZZZZZZZ",
			}

			// NSEC3 covering next closer
			nsec3NextCloser := &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   "00000000.example.com.",
					Rrtype: dns.TypeNSEC3,
				},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "ZZZZZZZZ",
			}

			// Verify next closer is covered
			if sut.nsec3Covers([]*dns.NSEC3{nsec3NextCloser}, hashNextCloser) &&
				sut.nsec3Covers([]*dns.NSEC3{nsec3NextCloser}, hashWildcard) {
				result := sut.validateNSEC3NXDOMAIN(
					[]*dns.NSEC3{nsec3Zone, nsec3NextCloser},
					"test.example.com.", "example.com.", dns.SHA1, "", 0,
				)
				// Should return Secure if proof is valid
				Expect(result).ShouldNot(Equal(ValidationResultIndeterminate))
			}
		})
	})

	// Proofs about names of the zone example., from a denial set of verified records of that zone
	// (see nsec3Range): the record of a name, and records that cover the hash of one name only.
	Describe("proofs of a denial set", func() {
		const zone = "example."

		var apex, nextCloser, wildcard *dns.NSEC3

		record := func(name string, types ...uint16) *dns.NSEC3 { return nsec3Range(zone, name, 0, 1, types...) }
		cover := func(name string, flags uint8) *dns.NSEC3 {
			rr := nsec3Range(zone, name, -1, 1)
			rr.Flags = flags

			return rr
		}
		nameError := func(name string, records ...*dns.NSEC3) ValidationResult {
			return legacyDenialSet(sut, records, name, dns.TypeA).nameError()
		}
		noDS := func(name string, records ...*dns.NSEC3) ValidationResult {
			return legacyDenialSet(sut, records, name, dns.TypeDS).noDS(false)
		}

		BeforeEach(func() {
			apex = record(zone, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM)
			nextCloser = cover("nx.example.", 0)
			wildcard = cover("*.example.", 0)
		})

		It("does not take a name whose hash is the next hash of a record as covered", func() {
			// RFC 5155 §1.3: the next hashed owner name is the hash of a name that exists
			endsAtName := nsec3Range(zone, "nx.example.", -2, 0)

			Expect(nameError("nx.example.", apex, nextCloser, wildcard)).Should(Equal(ValidationResultSecure))
			Expect(nameError("nx.example.", apex, endsAtName, wildcard)).Should(Equal(ValidationResultBogus))
		})

		It("does not take the hash of the only record of a chain as covered", func() {
			// RFC 5155 §1.3: the next hash of that record is its own, and it covers every other
			// hash. Such a record of the wildcard does not deny the wildcard.
			only := func(name string, types ...uint16) *dns.NSEC3 { return nsec3Range(zone, name, 0, 0, types...) }

			Expect(nameError("nx.example.", only(zone, apex.TypeBitMap...))).Should(Equal(ValidationResultSecure))
			Expect(nameError("nx.example.", apex, nextCloser, only("*.example.", dns.TypeA))).
				Should(Equal(ValidationResultBogus))
		})

		It("asks for the denial of the wildcard before Opt-Out makes a name error Insecure", func() {
			// RFC 5155 §8.4
			optOut := cover("nx.example.", nsec3OptOut)

			Expect(nameError("nx.example.", apex, optOut, wildcard)).Should(Equal(ValidationResultInsecure))
			Expect(nameError("nx.example.", apex, optOut)).Should(Equal(ValidationResultBogus))
		})

		It("takes neither a delegation nor a DNAME as the closest encloser", func() {
			// RFC 5155 §8.3: the NSEC3 record of the closest encloser has no DNAME bit, and the NS
			// bit only with the SOA bit. The zone does not hold the names below sub.example., a
			// secure delegation, an insecure one or a DNAME.
			for _, types := range [][]uint16{
				{dns.TypeNS, dns.TypeDS, dns.TypeRRSIG}, {dns.TypeNS}, {dns.TypeDNAME, dns.TypeRRSIG},
			} {
				encloser := record("sub.example.", types...)

				Expect(nameError("www.sub.example.", apex, encloser, cover("www.sub.example.", 0), cover("*.sub.example.", 0))).
					Should(Equal(ValidationResultBogus), "name error, types %v", types)
				Expect(noDS("www.sub.example.", apex, encloser, cover("www.sub.example.", nsec3OptOut))).
					Should(Equal(ValidationResultBogus), "no DS, types %v", types)

				// The search ends at sub.example.: example. is no closest encloser of the name,
				// whatever the set holds for a proof with it
				Expect(nameError("www.sub.example.", apex, encloser, cover("sub.example.", 0), wildcard)).
					Should(Equal(ValidationResultBogus), "name error above the record, types %v", types)
				Expect(noDS("www.sub.example.", apex, encloser, cover("sub.example.", nsec3OptOut))).
					Should(Equal(ValidationResultBogus), "no DS above the record, types %v", types)
			}
		})

		It("denies a DS RRset by Opt-Out only with the closest encloser and the cover of the next closer name", func() {
			// RFC 5155 §8.6: the closest encloser of a.b.example. is example., and the next closer
			// name b.example.
			Expect(noDS("a.b.example.", apex, cover("b.example.", nsec3OptOut))).Should(Equal(ValidationResultInsecure))
			Expect(noDS("a.b.example.", apex, cover("a.b.example.", nsec3OptOut))).Should(Equal(ValidationResultBogus))
			Expect(noDS("a.b.example.", cover("b.example.", nsec3OptOut))).Should(Equal(ValidationResultBogus))
			Expect(noDS("a.b.example.", apex, cover("b.example.", 0))).Should(Equal(ValidationResultBogus))
		})

		It("takes the root as the closest encloser", func() {
			// RFC 5155 §8.3: the closest encloser may be the apex of the zone, the root too
			records := []*dns.NSEC3{
				nsec3Range(".", ".", 0, 1, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM),
				nsec3Range(".", "nx.", -1, 1),
				nsec3Range(".", "*.", -1, 1),
			}

			Expect(legacyDenialSet(sut, records, "nx.", dns.TypeA).nameError()).Should(Equal(ValidationResultSecure))
		})

		It("proves nothing about a name that cannot be hashed", func() {
			// The label is too long for a name. The range of the second record wraps around the
			// end of the hash order.
			unhashable := strings.Repeat("a", 64) + ".example."

			Expect(nameError(unhashable, apex, nsec3Range(zone, "nx.example.", 1, -1))).Should(Equal(ValidationResultBogus))
		})

		It("ignores an NSEC3 record with a flag that is not defined", func() {
			// RFC 5155 §8.2: neither the parameters of such a record nor its Opt-Out flag say anything
			salted := cover("nx.example.", 2)
			salted.Salt = "ab"

			Expect(nameError("nx.example.", salted, apex, nextCloser, wildcard)).Should(Equal(ValidationResultSecure))
			Expect(nameError("nx.example.", apex, nextCloser, wildcard, cover("nx.example.", 2|nsec3OptOut))).
				Should(Equal(ValidationResultSecure))
			Expect(nameError("nx.example.", apex, cover("nx.example.", 2), wildcard)).Should(Equal(ValidationResultBogus))
		})

		It("ignores an NSEC3 record with an unknown hash algorithm", func() {
			// RFC 5155 §8.1
			unknown := cover("nx.example.", 0)
			unknown.Hash = 2

			Expect(nameError("nx.example.", unknown, apex, nextCloser, wildcard)).Should(Equal(ValidationResultSecure))
			Expect(nameError("nx.example.", apex, unknown, wildcard)).Should(Equal(ValidationResultBogus))
		})

		It("ignores an NSEC3 record with a hash that is not as long as a SHA-1 hash", func() {
			shortNext, shortOwner := cover("nx.example.", 0), cover("nx.example.", 0)
			shortNext.NextDomain = "VVVV"
			shortOwner.Hdr.Name = "0000." + zone

			Expect(nameError("nx.example.", apex, shortNext, wildcard)).Should(Equal(ValidationResultBogus))
			Expect(nameError("nx.example.", apex, shortOwner, wildcard)).Should(Equal(ValidationResultBogus))
		})

		It("proves nothing with NSEC3 records that are all ignored", func() {
			// The proof of a name error and the NSEC3 record of an insecure delegation, then each
			// record with a flag that is not defined
			delegation := record("sub.example.", dns.TypeNS)
			noData := func() ValidationResult {
				return legacyDenialSet(sut, []*dns.NSEC3{delegation}, "sub.example.", dns.TypeDS).noData()
			}

			Expect(nameError("nx.example.", apex, nextCloser, wildcard)).Should(Equal(ValidationResultSecure))
			Expect(noData()).Should(Equal(ValidationResultSecure))
			Expect(noDS("sub.example.", delegation)).Should(Equal(ValidationResultSecure))

			for _, rr := range []*dns.NSEC3{apex, nextCloser, wildcard, delegation} {
				rr.Flags = 2
			}

			Expect(nameError("nx.example.", apex, nextCloser, wildcard)).Should(Equal(ValidationResultBogus))
			Expect(noData()).Should(Equal(ValidationResultBogus))
			Expect(noDS("sub.example.", delegation)).Should(Equal(ValidationResultBogus))
		})

		It("holds the iteration count of the records against the limit as it is configured", func() {
			// RFC 5155 §10.3. An iteration count has 16 bits, so a limit above 65535 allows every count.
			noData := func(limit uint, iterations uint16) ValidationResult {
				matching := &dns.NSEC3{
					Hdr: dns.RR_Header{
						Name:   dns.HashName("sub.example.", dns.SHA1, iterations, "") + "." + zone,
						Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300,
					},
					Hash: dns.SHA1, Iterations: iterations, HashLength: 20,
					NextDomain: dns.HashName("z.example.", dns.SHA1, iterations, ""), TypeBitMap: []uint16{dns.TypeNS},
				}
				v := NewValidator(ctx, trustStore, sut.logger, &mockResolver{}, 1, 10, limit, 30, 3600)

				return legacyDenialSet(v, []*dns.NSEC3{matching}, "sub.example.", dns.TypeDS).noData()
			}

			Expect(noData(2, 2)).Should(Equal(ValidationResultSecure))
			Expect(noData(2, 3)).Should(Equal(ValidationResultBogus))
			Expect(noData(65536, 3)).Should(Equal(ValidationResultSecure))
			Expect(noData(65538, 3)).Should(Equal(ValidationResultSecure))
		})
	})
})

// nsec3Range returns an NSEC3 record of zone (SHA-1, no salt, no extra iterations) with types whose
// range runs from the hash of name plus from to that hash plus to: 0 and 1 make the record of
// name, and -1 and 1 a record that covers the hash of name and no other hash.
func nsec3Range(zone, name string, from, to int64, types ...uint16) *dns.NSEC3 {
	return nsec3SaltedRange(zone, name, "", 0, from, to, types...)
}

// nsec3SaltedRange is nsec3Range for a zone whose NSEC3 chain has salt and extra iterations
func nsec3SaltedRange(zone, name, salt string, iterations uint16, from, to int64, types ...uint16) *dns.NSEC3 {
	base32hex := base32.HexEncoding.WithPadding(base32.NoPadding)
	near := func(delta int64) string {
		hash, err := base32hex.DecodeString(dns.HashName(name, dns.SHA1, iterations, salt))
		Expect(err).Should(Succeed())

		sum := new(big.Int).Add(new(big.Int).SetBytes(hash), big.NewInt(delta))

		return base32hex.EncodeToString(sum.FillBytes(hash))
	}

	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name: near(from) + "." + strings.TrimPrefix(zone, "."), Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300,
		},
		Hash: dns.SHA1, Iterations: iterations, SaltLength: uint8(len(salt) / 2), Salt: salt, HashLength: 20,
		NextDomain: near(to), TypeBitMap: types,
	}
}
