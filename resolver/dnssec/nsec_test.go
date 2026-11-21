package dnssec

import (
	"context"
	"strings"

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
		ctx = withQueryBudget(ctx, 10)
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
			// and from example.com to a.example.com, which covers the wildcard *.example.com
			apex := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "a.example.com.",
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec, apex},
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
		// The NSEC record of the apex covers *.example.com., the wildcard that would answer for a name
		// below example.com. that does not exist (RFC 4035 §5.4)
		apex := &dns.NSEC{
			Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC},
			NextDomain: "a.example.com.",
		}

		It("should return Secure when NSEC records cover the query name and the wildcard", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}

			result := sut.validateNSECNXDOMAIN([]*dns.NSEC{nsec, apex}, "m.example.com.")
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should return Bogus when no NSEC covers the wildcard at the closest encloser", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}

			result := sut.validateNSECNXDOMAIN([]*dns.NSEC{nsec}, "m.example.com.")
			Expect(result).Should(Equal(ValidationResultBogus))
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
			result := sut.validateNSECNXDOMAIN([]*dns.NSEC{nsec, apex}, "m.example.com")
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

			// Query falls in second range (canonically between m and n)
			result := sut.validateNSECNXDOMAIN([]*dns.NSEC{nsec1, nsec2, nsec3, apex}, "ma.example.com.")
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should handle wrap-around at end of zone", func() {
			// The last NSEC record of a zone has the apex as its next owner name (RFC 4034 §4.1.1): the
			// zone of the records here is the root
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "z.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: ".",
			}

			// Query name after the last name of the zone
			result := sut.validateNSECNXDOMAIN([]*dns.NSEC{nsec, apex}, "zz.example.com.")
			Expect(result).Should(Equal(ValidationResultSecure))
		})

		It("should not take a record for the last of its zone that does not end at the apex", func() {
			// A next owner name before the owner name that is not the apex of the zone: no zone has
			// such a record, and it covers nothing
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "z.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "a.example.com.",
			}

			result := sut.validateNSECNXDOMAIN([]*dns.NSEC{nsec, apex}, "zz.example.com.")
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		// RFC 4470: a name server that signs its answers as it gives them makes the records that
		// cover a name and the wildcard for it. Their owner names and next owner names need not
		// exist.
		minimal := func(owner, next string) *dns.NSEC {
			return &dns.NSEC{
				Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC},
				NextDomain: next, TypeBitMap: []uint16{dns.TypeRRSIG, dns.TypeNSEC},
			}
		}

		It("should take records that end just after the name and the wildcard (RFC 4470 §3)", func() {
			records := []*dns.NSEC{
				minimal("fon.example.com.", "foo-.example.com."), minimal(").example.com.", "+.example.com."),
			}

			Expect(sut.validateNSECNXDOMAIN(records, "foo.example.com.")).Should(Equal(ValidationResultSecure))
		})

		It("should read a record that ends below the name as that of an empty non-terminal (RFC 4470 §4)", func() {
			// RFC 4592 §2.2.2: a name exists if a name below it does, and \000.foo.example.com. is
			// below foo.example.com. The name has no data then, and no name error.
			records := []*dns.NSEC{
				minimal("fon.example.com.", `\000.foo.example.com.`), minimal(").example.com.", "+.example.com."),
			}

			Expect(sut.validateNSECNXDOMAIN(records, "foo.example.com.")).Should(Equal(ValidationResultBogus))
			Expect(sut.validateNSECNODATA(records, "foo.example.com.", dns.TypeA)).Should(Equal(ValidationResultSecure))
		})

		It("should read a record that ends below the wildcard as that of an empty non-terminal (RFC 4470 §4)", func() {
			// RFC 4592 §4.9: a wildcard without records that has names below it exists, and answers
			// for the name without data
			records := []*dns.NSEC{
				minimal("fon.example.com.", "foo-.example.com."), minimal(").example.com.", `\000.*.example.com.`),
			}

			Expect(sut.validateNSECNXDOMAIN(records, "foo.example.com.")).Should(Equal(ValidationResultBogus))
			Expect(sut.validateNSECNODATA(records, "foo.example.com.", dns.TypeA)).Should(Equal(ValidationResultSecure))
		})

		It("should ask for the denial of the wildcard at the closest encloser that the records show", func() {
			// The record that covers a.b.example.com. has names below b.example.com., so that is the
			// closest encloser that it shows, and no record denies *.b.example.com.
			cover := minimal("`.b.example.com.", "a-.b.example.com.")

			Expect(sut.validateNSECNXDOMAIN([]*dns.NSEC{cover, minimal(").example.com.", "+.example.com.")},
				"a.b.example.com.")).Should(Equal(ValidationResultBogus))
			Expect(sut.validateNSECNXDOMAIN([]*dns.NSEC{cover, minimal(").b.example.com.", "+.b.example.com.")},
				"a.b.example.com.")).Should(Equal(ValidationResultSecure))
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
				TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA},
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

	// Proofs from a denial set of verified NSEC records of the zone example. A name is the same
	// name in every case (RFC 4343). A zone spells its names as it likes, and a reply spells the
	// owner names that it compresses against its question as the question does.
	Describe("NSEC record of a name that is spelt in another case", func() {
		record := func(owner string, types ...uint16) []*dns.NSEC {
			return []*dns.NSEC{{
				Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "z.example.",
				TypeBitMap: types,
			}}
		}

		It("proves that the name has no data of a type", func() {
			noData := func(owner, name string, qtype uint16) ValidationResult {
				return legacyDenialSet(sut, record(owner, dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC), name, qtype).noData()
			}

			Expect(noData("WWW.Example.", "www.example.", dns.TypeTXT)).Should(Equal(ValidationResultSecure))
			Expect(noData("www.example.", "WWW.Example.", dns.TypeTXT)).Should(Equal(ValidationResultSecure))
			Expect(noData("WWW.Example.", "www.example.", dns.TypeA)).Should(Equal(ValidationResultBogus),
				"the record says that the name has the type")
			Expect(noData("WWW.Example.", "ww.example.", dns.TypeTXT)).Should(Equal(ValidationResultBogus),
				"the record is that of another name")
		})

		It("proves that the name is an insecure delegation", func() {
			noDS := func(owner, name string, types ...uint16) ValidationResult {
				return legacyDenialSet(sut, record(owner, types...), name, dns.TypeDS).noDS(false)
			}

			Expect(noDS("Sub.Example.", "sub.example.", dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC)).
				Should(Equal(ValidationResultSecure))
			Expect(noDS("sub.example.", "SUB.EXAMPLE.", dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC)).
				Should(Equal(ValidationResultSecure))
			Expect(noDS("Sub.Example.", "sub.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)).
				Should(Equal(ValidationResultBogus), "the record is not that of a delegation")
		})
	})

	// Replies without answer for names of the zone example., as its name servers send them: the SOA
	// record and the NSEC records of the proof, each with the RRSIG of the zone (RFC 4035 §3.1.3).
	Describe("proof that a name has no data of a type", func() {
		var (
			chain *signedChain
			v     *Validator
		)

		BeforeEach(func() {
			chain = newSignedChain()
			v = NewValidator(ctx, chain.anchors, sut.logger, &mockResolver{ResolveFn: chain.resolve}, 1, 10, 150, 30, 3600)
		})

		// noData returns the status of the reply for name and qtype whose authority section holds
		// records, NSEC records in zone file format, after the SOA record.
		noData := func(name string, qtype uint16, records ...string) ValidationResult {
			records = append([]string{"example. 300 IN SOA ns.example. host.example. 1 3600 600 86400 300"}, records...)
			authority := make([]dns.RR, 0, 2*len(records))

			for _, record := range records {
				rr, err := dns.NewRR(record)
				Expect(err).Should(Succeed())

				sig := signRRset([]dns.RR{rr}, rr.Header().Rrtype, chain.parentKey, chain.parentPriv, chain.parent)
				authority = append(authority, rr, sig)
			}

			question := dns.Question{Name: name, Qtype: qtype, Qclass: dns.ClassINET}

			return v.ValidateResponse(ctx, &dns.Msg{Ns: authority}, question)
		}

		It("is given for an empty non-terminal by the record before it, which names a name below it", func() {
			// _tcp.example. has no records, and names below it have (RFC 4592 §2.2.2)
			Expect(noData("_tcp.example.", dns.TypeA, "_github.example. 300 IN NSEC _25._tcp.example. TXT RRSIG NSEC")).
				Should(Equal(ValidationResultSecure))

			// The record before the name may be that of a wildcard
			Expect(noData("_dane.example.", dns.TypeA, "*.example. 300 IN NSEC batch._dane.example. TXT RRSIG NSEC")).
				Should(Equal(ValidationResultSecure))

			Expect(noData("_tcp.example.", dns.TypeA, "_github.example. 300 IN NSEC _udp.example. TXT RRSIG NSEC")).
				Should(Equal(ValidationResultBogus), "the next owner name is not below the name, which so does not exist")
			Expect(noData("_tcp.example.", dns.TypeA, "_25._tcp.example. 300 IN NSEC _443._tcp.example. RRSIG NSEC TLSA")).
				Should(Equal(ValidationResultBogus), "the record is not the one before the name")
		})

		It("is given for a name that a wildcard answers for by the record of the wildcard, without the type", func() {
			// RFC 4035 §3.1.3.4: a record covers the name, and so shows the closest encloser example.,
			// and the record of *.example. lists the types that the wildcard answers with
			const (
				wildcard = "*.example. 300 IN NSEC _acme-challenge.example. A AAAA RRSIG NSEC"
				cover    = "_psl.example. 300 IN NSEC lotus.example. TXT RRSIG NSEC"
				last     = "_443._tcp.www.example. 300 IN NSEC example. CNAME RRSIG NSEC"
			)

			Expect(noData("college.example.", dns.TypeHTTPS, wildcard, cover)).Should(Equal(ValidationResultSecure))
			Expect(noData("zz9x.example.", dns.TypeHTTPS, last, wildcard)).
				Should(Equal(ValidationResultSecure), "the last record of the zone covers the name")

			Expect(noData("college.example.", dns.TypeHTTPS, wildcard)).
				Should(Equal(ValidationResultBogus), "no record covers the name")
			Expect(noData("college.example.", dns.TypeAAAA, wildcard, cover)).
				Should(Equal(ValidationResultBogus), "the wildcard has the type")
			Expect(noData("college.example.", dns.TypeHTTPS, cover)).
				Should(Equal(ValidationResultBogus), "the record of the wildcard is missing")
			Expect(noData("x.lotus.example.", dns.TypeHTTPS, wildcard, "lotus.example. 300 IN NSEC ns.example. A RRSIG NSEC")).
				Should(Equal(ValidationResultBogus), "lotus.example. exists, so *.example. does not answer for a name below it")
		})

		It("takes no wildcard from a record of a zone that the name is not in", func() {
			// alias.example. is above the zone below.alias.example., whose last record is the first one
			// here. A record of a zone that the name is not in shows no closest encloser above the name,
			// and the wildcard below alias.example. does not answer for alias.example. itself.
			records := []*dns.NSEC{
				{
					Hdr:        dns.RR_Header{Name: "www.below.alias.example.", Rrtype: dns.TypeNSEC},
					NextDomain: "below.alias.example.",
					TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
				},
				{
					Hdr:        dns.RR_Header{Name: "*.alias.example.", Rrtype: dns.TypeNSEC},
					NextDomain: "below.alias.example.",
					TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
				},
			}

			Expect(sut.validateNSECNODATA(records, "alias.example.", dns.TypeTXT)).Should(Equal(ValidationResultBogus))
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
			// The last NSEC record of a zone has the apex as its next owner name (RFC 4034 §4.1.1): the
			// zone of the record here is the root
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "z.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: ".",
			}

			// Names after z should be covered
			Expect(sut.nsecCoversName(nsec, "zz.example.com.")).Should(BeTrue())
			// Names before z are those of the records before it
			Expect(sut.nsecCoversName(nsec, "0.example.com.")).Should(BeFalse())
			Expect(sut.nsecCoversName(nsec, "m.example.com.")).Should(BeFalse())
		})

		It("should let no record but the last of a zone wrap around", func() {
			// A next owner name before the owner name that is not the apex of the zone
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "z.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "a.example.com.",
			}

			Expect(sut.nsecCoversName(nsec, "zz.example.com.")).Should(BeFalse())
			Expect(sut.nsecCoversName(nsec, "0.example.com.")).Should(BeFalse())
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

			// Subdomain should be covered (canonically a < sub.m < z)
			Expect(sut.nsecCoversName(nsec, "sub.m.example.com.")).Should(BeTrue())
		})

		It("should cover underscore-prefixed subdomains using canonical ordering (issue #1969)", func() {
			// Exact scenario from https://github.com/0xERR0R/blocky/issues/1969
			// RFC 4034 §6.1 canonical order: mail... < _25._tcp.mail... < pop...
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "mail.boegli-bestattungen.ch.", Rrtype: dns.TypeNSEC},
				NextDomain: "pop.boegli-bestattungen.ch.",
			}

			Expect(sut.nsecCoversName(nsec, "_25._tcp.mail.boegli-bestattungen.ch.")).Should(BeTrue())
		})

		It("should cover other underscore-prefixed names correctly", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "mail.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "pop.example.com.",
			}

			Expect(sut.nsecCoversName(nsec, "_dmarc.mail.example.com.")).Should(BeTrue())
			Expect(sut.nsecCoversName(nsec, "_acme-challenge.mail.example.com.")).Should(BeTrue())
		})

		It("should not cover underscore-prefixed names outside the NSEC range", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "b.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "c.example.com.",
			}

			// _a.a.example.com. is canonically before b.example.com. (a < b at third label)
			Expect(sut.nsecCoversName(nsec, "_a.a.example.com.")).Should(BeFalse())
		})

		It("should handle wrap-around with underscore-prefixed subdomains", func() {
			// The last record of the zone, which is the root here
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "z.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: ".",
			}

			// _srv.z.example.com. is canonically after z.example.com.
			Expect(sut.nsecCoversName(nsec, "_srv.z.example.com.")).Should(BeTrue())
		})
	})

	Describe("canonicalNameCompare", func() {
		It("should order names at the same level alphabetically", func() {
			Expect(canonicalNameCompare("a.example.com.", "z.example.com.")).Should(BeNumerically("<", 0))
			Expect(canonicalNameCompare("z.example.com.", "a.example.com.")).Should(BeNumerically(">", 0))
		})

		It("should return 0 for equal names", func() {
			Expect(canonicalNameCompare("a.example.com.", "a.example.com.")).Should(Equal(0))
		})

		It("should be case insensitive", func() {
			Expect(canonicalNameCompare("A.EXAMPLE.COM.", "a.example.com.")).Should(Equal(0))
		})

		It("should sort shorter name before longer when labels match as prefix", func() {
			// example.com. < a.example.com. (fewer labels first)
			Expect(canonicalNameCompare("example.com.", "a.example.com.")).Should(BeNumerically("<", 0))
			// mail.example.com. < _tcp.mail.example.com.
			Expect(canonicalNameCompare("mail.example.com.", "_tcp.mail.example.com.")).Should(BeNumerically("<", 0))
		})

		It("should compare labels right to left (not string left to right)", func() {
			// Key insight: canonical ordering differs from string ordering here.
			// String comparison: "_25._tcp.mail..." < "mail..." (because '_' < 'm')
			// Canonical comparison: "mail..." < "_25._tcp.mail..." (shared labels match, shorter first)
			Expect(canonicalNameCompare(
				"mail.boegli-bestattungen.ch.",
				"_25._tcp.mail.boegli-bestattungen.ch.",
			)).Should(BeNumerically("<", 0))
		})

		It("should compare differing labels at the correct depth", func() {
			// Both share example.com., differ at third label from right: a vs b
			Expect(canonicalNameCompare("sub.a.example.com.", "sub.b.example.com.")).Should(BeNumerically("<", 0))
			// Differ at second label from right
			Expect(canonicalNameCompare("a.foo.com.", "a.bar.com.")).Should(BeNumerically(">", 0))
		})

		It("should handle root and TLD names", func() {
			Expect(canonicalNameCompare("com.", "org.")).Should(BeNumerically("<", 0))
			Expect(canonicalNameCompare(".", "com.")).Should(BeNumerically("<", 0))
		})

		It("should handle names without trailing dot", func() {
			Expect(canonicalNameCompare("a.example.com", "z.example.com")).Should(BeNumerically("<", 0))
		})

		It("should sort the names of the example in RFC 4034 §6.1", func() {
			sorted := []string{
				"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.", "z.example.",
				`\001.z.example.`, "*.z.example.", `\200.z.example.`,
			}

			for i, name := range sorted {
				for _, later := range sorted[i+1:] {
					Expect(canonicalNameCompare(name, later)).Should(BeNumerically("<", 0), "%s before %s", name, later)
					Expect(canonicalNameCompare(later, name)).Should(BeNumerically(">", 0), "%s after %s", later, name)
				}
			}
		})

		It("should order labels by their octets, not by the text that escapes them", func() {
			// A space is the octet 0x20, which is before "-" (0x2d), and a dot inside a label is no end
			// of the label
			Expect(canonicalNameCompare(`lab\ printer.example.`, "lab-2.example.")).Should(BeNumerically("<", 0))
			Expect(canonicalNameCompare(`lab\032printer.example.`, `lab\ printer.example.`)).Should(Equal(0))
			Expect(canonicalNameCompare(`a\.b.example.`, "a.example.")).Should(BeNumerically(">", 0))
			Expect(canonicalNameCompare(`a\.b.example.`, "b.example.")).Should(BeNumerically("<", 0))

			// Only US-ASCII letters have another case
			Expect(canonicalNameCompare(`\065.example.`, "a.example.")).Should(Equal(0))
			Expect(canonicalNameCompare(`\201.example.`, `\233.example.`)).Should(BeNumerically("<", 0))

			// A label is before a longer one that starts with it
			Expect(canonicalNameCompare("lab.example.", `lab\000.example.`)).Should(BeNumerically("<", 0))
		})

		It("should let no record own or cover a name that cannot be on the wire", func() {
			// Like a name with a label of 64 octets (RFC 1035 §2.3.4). The first record is the last
			// of its zone, the root here, and covers every name after its owner name.
			tooLong := strings.Repeat("x", 64) + ".example.com."
			last := &dns.NSEC{Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC}, NextDomain: "."}
			own := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: tooLong, Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.", TypeBitMap: []uint16{dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC},
			}

			Expect(sut.nsecCoversName(last, tooLong[1:])).Should(BeTrue())
			Expect(sut.nsecCoversName(last, tooLong)).Should(BeFalse())
			Expect(sut.validateNSECNODATA([]*dns.NSEC{own}, tooLong, dns.TypeA)).Should(Equal(ValidationResultBogus))
		})
	})

	// Replies for names of the zone example., as its name servers send them. The zone has the names
	// lab and "lab printer", whose text escapes the space: names are ordered by the octets of their
	// labels (RFC 4034 §6.1), where the space (0x20) is before "-" (0x2d).
	Describe("proof that a name with an octet that its text escapes does not exist", func() {
		var (
			chain *signedChain
			v     *Validator
		)

		BeforeEach(func() {
			chain = newSignedChain()
			v = NewValidator(ctx, chain.anchors, sut.logger, &mockResolver{ResolveFn: chain.resolve}, 1, 10, 150, 30, 3600)
		})

		// nameError returns the status of the name error reply for name whose authority section holds
		// records, NSEC records in zone file format, after the SOA record.
		nameError := func(name string, records ...string) ValidationResult {
			records = append([]string{"example. 300 IN SOA ns.example. host.example. 1 3600 600 86400 300"}, records...)
			authority := make([]dns.RR, 0, 2*len(records))

			for _, record := range records {
				rr, err := dns.NewRR(record)
				Expect(err).Should(Succeed())

				sig := signRRset([]dns.RR{rr}, rr.Header().Rrtype, chain.parentKey, chain.parentPriv, chain.parent)
				authority = append(authority, rr, sig)
			}

			question := dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}

			return v.ValidateResponse(ctx, &dns.Msg{Rcode: dns.RcodeNameError, Ns: authority}, question)
		}

		It("is given by the records before and after the name in the order of their octets", func() {
			const apex = "example. 300 IN NSEC lab.example. NS SOA RRSIG NSEC DNSKEY"

			// The last record of the zone covers lab-2.example., which is after "lab printer"
			Expect(nameError("lab-2.example.", `lab\032printer.example. 300 IN NSEC example. A RRSIG NSEC`, apex)).
				Should(Equal(ValidationResultSecure))

			// In a zone that has lab-2.example., the record of lab ends at "lab printer", before it
			Expect(nameError("lab-2.example.", `lab.example. 300 IN NSEC lab\032printer.example. A RRSIG NSEC`, apex)).
				Should(Equal(ValidationResultBogus))
		})

		It("has the closest encloser that the octets of the labels show", func() {
			// The zone has "lab printer" with the names a and z below it. m is a name below it too,
			// however a reply spells the space: "lab printer" is its closest encloser, and the record
			// of "lab printer" covers the wildcard below it.
			const (
				above = `lab\032printer.example. 300 IN NSEC a.lab\032printer.example. TXT RRSIG NSEC`
				cover = `a.lab\032printer.example. 300 IN NSEC z.lab\032printer.example. A RRSIG NSEC`
			)

			Expect(nameError(`m.lab\ printer.example.`, cover, above)).Should(Equal(ValidationResultSecure))
			Expect(nameError(`m.lab\ printer.example.`, cover)).
				Should(Equal(ValidationResultBogus), "without the denial of the wildcard")
		})

		It("is given by the records that a name server makes for the name alone (RFC 4470 §3)", func() {
			// A record from just before foo.example. to just after it, and one around the wildcard
			// *.example.: the octet before "*" is ")", which the text of a name escapes
			Expect(nameError("foo.example.", "fon.example. 300 IN NSEC foo-.example. RRSIG NSEC",
				`\).example. 300 IN NSEC +.example. RRSIG NSEC`)).Should(Equal(ValidationResultSecure))
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
