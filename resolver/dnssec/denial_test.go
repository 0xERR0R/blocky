package dnssec

import (
	"context"
	"slices"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Denial of existence validation", func() {
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

		mockUpstream = &mockResolver{ResolveFn: benignEmptyResolve}
		logger, _ := log.NewMockEntry()

		sut = NewValidator(ctx, trustStore, logger, mockUpstream, 1, 10, 150, 30, 3600)
		ctx = withQueryBudget(ctx, 10)
	})

	Describe("ANY NODATA", func() {
		It("distinguishes an NSEC owner from an empty non-terminal in the interval", func() {
			rr := &dns.NSEC{
				Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeNSEC}, NextDomain: "leaf.b.example.",
				TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
			}
			proof := func(name string) ValidationResult {
				return legacyDenialSet(sut, []*dns.NSEC{rr}, name, dns.TypeANY).noData()
			}
			Expect(proof("b.example.")).Should(Equal(ValidationResultSecure))
			Expect(proof(rr.Hdr.Name)).Should(Equal(ValidationResultBogus))
			// The NSEC RRset itself exists regardless of the listed types.
			rr.TypeBitMap = nil
			Expect(proof(rr.Hdr.Name)).Should(Equal(ValidationResultBogus))
		})

		It("requires an empty bitmap at the original name for an NSEC3 match", func() {
			d := denialSet{name: "b.example.", qtype: dns.TypeANY, logger: sut.logger}
			Expect(d.nsec3MatchNoData(&dns.NSEC3{})).Should(Equal(ValidationResultSecure))
			Expect(d.nsec3MatchNoData(&dns.NSEC3{TypeBitMap: []uint16{dns.TypeTXT}})).Should(Equal(ValidationResultBogus))
		})
	})

	Describe("validateDenialOfExistence", func() {
		It("should return Bogus when no NSEC or NSEC3 records", func() {
			response := &dns.Msg{
				Ns: []dns.RR{},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			result := sut.validateDenialOfExistence(ctx, response, question)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should handle non-NSEC/NSEC3 records in authority section", func() {
			soa := &dns.SOA{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA},
			}
			ns := &dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS},
			}

			response := &dns.Msg{
				Ns: []dns.RR{soa, ns},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			result := sut.validateDenialOfExistence(ctx, response, question)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		It("should return early when authority section validation fails with Insecure", func() {
			// Create NSEC record without valid signature
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
				NextDomain: "z.example.com.",
			}

			// Mock upstream to return empty DNSKEY (causing validation to fail)
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
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "m.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			// Authority section validation should fail
			result := sut.validateDenialOfExistence(ctx, response, question)
			// Result should not be Secure since authority section validation failed
			Expect(result).ShouldNot(Equal(ValidationResultSecure))
		})

		It("should return early when authority section validation fails with Bogus", func() {
			// Create NSEC record with invalid signature
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
				NextDomain: "z.example.com.",
			}
			rrsig := &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
				TypeCovered: dns.TypeNSEC,
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec, rrsig},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "m.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			// Authority section validation should fail
			result := sut.validateDenialOfExistence(ctx, response, question)
			Expect(result).ShouldNot(Equal(ValidationResultSecure))
		})

		It("should handle empty authority section", func() {
			response := &dns.Msg{
				Ns: []dns.RR{},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			result := sut.validateDenialOfExistence(ctx, response, question)
			Expect(result).Should(Equal(ValidationResultBogus))
		})

		When("authority section validation succeeds", func() {
			It("should proceed to NSEC validation when authority is valid", func() {
				// Create a response with only SOA (no NSEC/NSEC3) and no signatures
				// This simulates the path after successful authority validation
				// where we check for NSEC/NSEC3 records
				response := &dns.Msg{
					Ns: []dns.RR{
						&dns.SOA{
							Hdr: dns.RR_Header{
								Name:   "example.com.",
								Rrtype: dns.TypeSOA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							Ns:      "ns1.example.com.",
							Mbox:    "admin.example.com.",
							Serial:  2024010101,
							Refresh: 3600,
							Retry:   600,
							Expire:  86400,
							Minttl:  300,
						},
					},
				}
				response.Rcode = dns.RcodeNameError

				question := dns.Question{
					Name:   "nonexistent.example.com.",
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}

				// Without RRSIG the SOA is unsigned data, which is Bogus under the root trust anchor
				// unless a delegation above it is proven to be unsigned
				result := sut.validateDenialOfExistence(ctx, response, question)
				Expect(result).Should(Equal(ValidationResultBogus))
			})
		})
	})

	// RFC 5155 §10.4: a server answers with the records of one chain of a zone. A reply that a
	// resolver put together while the zone changed from one chain to the other may hold records of
	// both, and each chain is a signed statement of the zone.
	Describe("a denial set with NSEC and NSEC3 records of the zone example.", func() {
		nsec := func(owner, next string, types ...uint16) dns.RR {
			return &dns.NSEC{
				Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: next, TypeBitMap: types,
			}
		}
		// The NSEC3 record of a name, and one that covers the hash of a name and no other
		nsec3 := func(name string, types ...uint16) dns.RR { return nsec3Range("example.", name, 0, 1, types...) }
		nsec3Cover := func(name string) dns.RR { return nsec3Range("example.", name, -1, 1) }
		secure := func(proof func(d *denialSet) ValidationResult) func(d *denialSet) bool {
			return func(d *denialSet) bool { return proof(d) == ValidationResultSecure }
		}

		// byNSEC and byNSEC3 return the records of either chain that give the proof. Neither gives
		// it without its last record.
		DescribeTable("proves with its NSEC records and, if that proof does not hold, with its NSEC3 records",
			func(name string, qtype uint16, holds func(d *denialSet) bool, byNSEC, byNSEC3 func() []dns.RR) {
				proves := func(records ...[]dns.RR) bool {
					return holds(legacyDenialSet(sut, slices.Concat(records...), name, qtype))
				}

				n, h := byNSEC(), byNSEC3()
				fewerN, fewerH := n[:len(n)-1], h[:len(h)-1]

				Expect(proves(n)).Should(BeTrue())
				Expect(proves(h)).Should(BeTrue())
				Expect(proves(fewerN)).Should(BeFalse())
				Expect(proves(fewerH)).Should(BeFalse())

				Expect(proves(n, h)).Should(BeTrue())
				Expect(proves(h, n)).Should(BeTrue(), "in either order of the section")
				Expect(proves(n, fewerH)).Should(BeTrue(), "the NSEC records give the proof")
				Expect(proves(fewerN, h)).Should(BeTrue(), "the NSEC3 records give the proof")
				Expect(proves(fewerN, fewerH)).Should(BeFalse())
			},
			Entry("that a name does not exist", "nx.example.", dns.TypeA, secure((*denialSet).nameError),
				func() []dns.RR {
					return []dns.RR{
						nsec("a.example.", "z.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
						nsec("example.", "a.example.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY),
					}
				},
				func() []dns.RR {
					return []dns.RR{
						nsec3("example.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM),
						nsec3Cover("nx.example."),
						nsec3Cover("*.example."),
					}
				}),
			Entry("that a name has no data of a type", "www.example.", dns.TypeTXT, secure((*denialSet).noData),
				func() []dns.RR {
					return []dns.RR{
						nsec("a.example.", "www.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
						nsec("www.example.", "z.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
					}
				},
				func() []dns.RR {
					return []dns.RR{
						nsec3("a.example.", dns.TypeA, dns.TypeRRSIG),
						nsec3("www.example.", dns.TypeA, dns.TypeRRSIG),
					}
				}),
			Entry("that a name is an insecure delegation", "sub.example.", dns.TypeDS,
				secure(func(d *denialSet) ValidationResult { return d.noDS(false) }),
				func() []dns.RR {
					return []dns.RR{
						nsec("a.example.", "sub.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
						nsec("sub.example.", "z.example.", dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC),
					}
				},
				func() []dns.RR {
					return []dns.RR{
						nsec3("a.example.", dns.TypeA, dns.TypeRRSIG),
						nsec3("sub.example.", dns.TypeNS),
					}
				}),
			Entry("that a name is no zone cut", "www.example.", dns.TypeDS, (*denialSet).noZoneCut,
				func() []dns.RR {
					return []dns.RR{
						nsec("a.example.", "www.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
						nsec("www.example.", "z.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
					}
				},
				func() []dns.RR {
					return []dns.RR{
						nsec3("a.example.", dns.TypeA, dns.TypeRRSIG),
						nsec3("www.example.", dns.TypeA, dns.TypeRRSIG),
					}
				}),
		)
	})
})
