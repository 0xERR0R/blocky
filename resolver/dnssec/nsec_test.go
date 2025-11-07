package dnssec

import (
	"context"

	"github.com/0xERR0R/blocky/log"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NSEC validation", func() {
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
		ctx = context.WithValue(ctx, queryBudgetKey{}, 10)
	})

	Describe("extractNSECRecords", func() {
		It("should extract NSEC records from RR slice", func() {
			nsec1 := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "b.example.com.",
			}
			nsec2 := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "b.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "c.example.com.",
			}
			soa := &dns.SOA{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA},
			}

			rrs := []dns.RR{nsec1, soa, nsec2}
			nsecs := extractNSECRecords(rrs)

			Expect(nsecs).Should(HaveLen(2))
			Expect(nsecs[0]).Should(Equal(nsec1))
			Expect(nsecs[1]).Should(Equal(nsec2))
		})

		It("should return empty slice when no NSEC records", func() {
			soa := &dns.SOA{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA},
			}
			ns := &dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS},
			}

			rrs := []dns.RR{soa, ns}
			nsecs := extractNSECRecords(rrs)

			Expect(nsecs).Should(BeEmpty())
		})

		It("should handle empty RR slice", func() {
			nsecs := extractNSECRecords([]dns.RR{})
			Expect(nsecs).Should(BeEmpty())
		})

		It("should handle nil RR slice", func() {
			nsecs := extractNSECRecords(nil)
			Expect(nsecs).Should(BeEmpty())
		})
	})

	Describe("validateNSECDenialOfExistence", func() {
		It("should return Insecure when no NSEC records present", func() {
			response := &dns.Msg{
				Ns: []dns.RR{},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "test.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			result := sut.validateNSECDenialOfExistence(response, question)
			Expect(result).Should(Equal(ValidationResultInsecure))
		})

		It("should validate NXDOMAIN when RCODE is NXDOMAIN", func() {
			// NSEC covers name range from a.example.com to z.example.com
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "m.example.com.", // Falls between a and z
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			result := sut.validateNSECDenialOfExistence(response, question)
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should validate NODATA when RCODE is not NXDOMAIN", func() {
			// NSEC at exact name with A record but not AAAA
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
				TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA},
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec},
			}
			response.Rcode = dns.RcodeSuccess // NODATA

			question := dns.Question{
				Name:   "example.com.",
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			}

			result := sut.validateNSECDenialOfExistence(response, question)
			Expect(result).Should(Equal(ValidationResultSecure))
		})
	})

	Describe("validateNSECNXDOMAIN", func() {
		It("should return Secure when NSEC covers the query name", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}

			result := sut.validateNSECNXDOMAIN([]*dns.NSEC{nsec}, "m.example.com.")
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should return Bogus when no NSEC covers the query name", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "b.example.com.",
			}

			result := sut.validateNSECNXDOMAIN([]*dns.NSEC{nsec}, "z.example.com.")
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should normalize query name to FQDN", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}

			// Test without trailing dot
			result := sut.validateNSECNXDOMAIN([]*dns.NSEC{nsec}, "m.example.com")
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should handle multiple NSEC records", func() {
			nsec1 := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "b.example.com.",
			}
			nsec2 := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "m.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "n.example.com.",
			}
			nsec3 := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "x.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}

			// Query falls in second range
			result := sut.validateNSECNXDOMAIN([]*dns.NSEC{nsec1, nsec2, nsec3}, "m.example.com.5")
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should handle wrap-around at end of zone", func() {
			// NSEC wraps from z back to a (covers end of zone)
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "z.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "a.example.com.",
			}

			// Query name that wraps around (after z or before a)
			result := sut.validateNSECNXDOMAIN([]*dns.NSEC{nsec}, "zz.example.com.")
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should return Bogus for empty NSEC list", func() {
			result := sut.validateNSECNXDOMAIN([]*dns.NSEC{}, "test.example.com.")
			Expect(result).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("validateNSECNODATA", func() {
		It("should return Secure when NSEC matches name and type not in bitmap", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
				TypeBitMap: []uint16{dns.TypeA, dns.TypeNS},
			}

			result := sut.validateNSECNODATA([]*dns.NSEC{nsec}, "example.com.", dns.TypeAAAA)
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should return Bogus when NSEC matches name but type exists in bitmap", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
				TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA},
			}

			result := sut.validateNSECNODATA([]*dns.NSEC{nsec}, "example.com.", dns.TypeAAAA)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return Bogus when no NSEC matches the query name", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "other.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
				TypeBitMap: []uint16{dns.TypeA},
			}

			result := sut.validateNSECNODATA([]*dns.NSEC{nsec}, "example.com.", dns.TypeA)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should normalize query name to FQDN", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
				TypeBitMap: []uint16{dns.TypeA},
			}

			// Test without trailing dot
			result := sut.validateNSECNODATA([]*dns.NSEC{nsec}, "example.com", dns.TypeAAAA)
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should handle multiple NSEC records", func() {
			nsec1 := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "b.example.com.",
				TypeBitMap: []uint16{dns.TypeA},
			}
			nsec2 := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "test.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
				TypeBitMap: []uint16{dns.TypeA},
			}

			result := sut.validateNSECNODATA([]*dns.NSEC{nsec1, nsec2}, "test.example.com.", dns.TypeAAAA)
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should return Bogus for empty NSEC list", func() {
			result := sut.validateNSECNODATA([]*dns.NSEC{}, "test.example.com.", dns.TypeA)
			Expect(result).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("nsecCoversName", func() {
		It("should return true when name is covered in normal range", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}

			Expect(sut.nsecCoversName(nsec, "m.example.com.")).Should(BeTrue())
			Expect(sut.nsecCoversName(nsec, "b.example.com.")).Should(BeTrue())
			Expect(sut.nsecCoversName(nsec, "y.example.com.")).Should(BeTrue())
		})

		It("should return false when name equals owner", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}

			Expect(sut.nsecCoversName(nsec, "a.example.com.")).Should(BeFalse())
		})

		It("should return false when name equals next domain", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}

			Expect(sut.nsecCoversName(nsec, "z.example.com.")).Should(BeFalse())
		})

		It("should return false when name is outside normal range", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "m.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "n.example.com.",
			}

			Expect(sut.nsecCoversName(nsec, "a.example.com.")).Should(BeFalse())
			Expect(sut.nsecCoversName(nsec, "z.example.com.")).Should(BeFalse())
		})

		It("should handle wrap-around case", func() {
			// NSEC wraps from z back to a
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "z.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "a.example.com.",
			}

			// Names after z should be covered
			Expect(sut.nsecCoversName(nsec, "zz.example.com.")).Should(BeTrue())
			// Names before a should be covered (wrap around)
			Expect(sut.nsecCoversName(nsec, "0.example.com.")).Should(BeTrue())
			// Names in normal range (a to z) should NOT be covered
			Expect(sut.nsecCoversName(nsec, "m.example.com.")).Should(BeFalse())
		})

		It("should use canonical name ordering", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "A.EXAMPLE.COM.", Rrtype: dns.TypeNSEC},
				NextDomain: "Z.EXAMPLE.COM.",
			}

			// Should work with mixed case
			Expect(sut.nsecCoversName(nsec, "m.example.com.")).Should(BeTrue())
			Expect(sut.nsecCoversName(nsec, "M.EXAMPLE.COM.")).Should(BeTrue())
		})

		It("should handle names with different label counts", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}

			// Subdomain should be covered
			Expect(sut.nsecCoversName(nsec, "sub.m.example.com.")).Should(BeTrue())
		})
	})

	Describe("nsecHasType", func() {
		It("should return true when type is in bitmap", func() {
			nsec := &dns.NSEC{
				TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS},
			}

			Expect(sut.nsecHasType(nsec, dns.TypeA)).Should(BeTrue())
			Expect(sut.nsecHasType(nsec, dns.TypeAAAA)).Should(BeTrue())
			Expect(sut.nsecHasType(nsec, dns.TypeNS)).Should(BeTrue())
		})

		It("should return false when type is not in bitmap", func() {
			nsec := &dns.NSEC{
				TypeBitMap: []uint16{dns.TypeA, dns.TypeNS},
			}

			Expect(sut.nsecHasType(nsec, dns.TypeAAAA)).Should(BeFalse())
			Expect(sut.nsecHasType(nsec, dns.TypeMX)).Should(BeFalse())
		})

		It("should return false for empty bitmap", func() {
			nsec := &dns.NSEC{
				TypeBitMap: []uint16{},
			}

			Expect(sut.nsecHasType(nsec, dns.TypeA)).Should(BeFalse())
		})

		It("should handle nil bitmap", func() {
			nsec := &dns.NSEC{
				TypeBitMap: nil,
			}

			Expect(sut.nsecHasType(nsec, dns.TypeA)).Should(BeFalse())
		})

		It("should handle all common DNS types", func() {
			nsec := &dns.NSEC{
				TypeBitMap: []uint16{
					dns.TypeA, dns.TypeNS, dns.TypeCNAME, dns.TypeSOA,
					dns.TypeMX, dns.TypeTXT, dns.TypeAAAA, dns.TypeDNSKEY,
					dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDS,
				},
			}

			Expect(sut.nsecHasType(nsec, dns.TypeA)).Should(BeTrue())
			Expect(sut.nsecHasType(nsec, dns.TypeDNSKEY)).Should(BeTrue())
			Expect(sut.nsecHasType(nsec, dns.TypeRRSIG)).Should(BeTrue())
			Expect(sut.nsecHasType(nsec, dns.TypeNSEC3)).Should(BeFalse())
		})
	})
})
