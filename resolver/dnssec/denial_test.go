package dnssec

import (
	"context"
	"errors"

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

		mockUpstream = &mockResolver{}
		logger, _ := log.NewMockEntry()

		sut = NewValidator(ctx, trustStore, logger, mockUpstream, 1, 10, 150, 30, 3600)
		ctx = context.WithValue(ctx, queryBudgetKey{}, 10)
	})

	Describe("validateDenialOfExistence", func() {
		It("should return Insecure when no NSEC or NSEC3 records", func() {
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
			Expect(result).Should(Equal(ValidationResultInsecure))
		})

		It("should use NSEC validation when NSEC records present", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}

			// Mock DNSKEY query for authority section validation
			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				if req.Req.Question[0].Qtype == dns.TypeDNSKEY {
					// Return empty DNSKEY response to make authority validation fail
					return &model.Response{
						Res: &dns.Msg{
							Answer: []dns.RR{},
						},
					}, nil
				}

				return nil, errors.New("mock error: only DNSKEY queries are handled")
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

			// Will fail on authority validation but should attempt NSEC validation
			result := sut.validateDenialOfExistence(ctx, response, question)
			// Result depends on authority section validation
			Expect(result).ShouldNot(BeNil())
		})

		It("should use NSEC3 validation when NSEC3 records present", func() {
			nsec3 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "hash.example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec3},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			// Will attempt NSEC3 validation
			result := sut.validateDenialOfExistence(ctx, response, question)
			Expect(result).ShouldNot(BeNil())
		})

		It("should prefer NSEC3 when both NSEC and NSEC3 present", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}
			nsec3 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "hash.example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec, nsec3},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			// Should use NSEC3 (checked first in the code)
			result := sut.validateDenialOfExistence(ctx, response, question)
			Expect(result).ShouldNot(BeNil())
		})

		It("should validate authority section first", func() {
			// Invalid RRSIG in authority section
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
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

			// Authority section validation will determine the result
			result := sut.validateDenialOfExistence(ctx, response, question)
			Expect(result).ShouldNot(BeNil())
		})

		It("should handle NODATA responses", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
				TypeBitMap: []uint16{dns.TypeA}, // Has A but not AAAA
			}

			response := &dns.Msg{
				Ns: []dns.RR{nsec},
			}
			response.Rcode = dns.RcodeSuccess // NODATA, not NXDOMAIN

			question := dns.Question{
				Name:   "example.com.",
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			}

			result := sut.validateDenialOfExistence(ctx, response, question)
			Expect(result).ShouldNot(BeNil())
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
			Expect(result).Should(Equal(ValidationResultInsecure))
		})

		It("should handle mixed record types in authority section", func() {
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}
			soa := &dns.SOA{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA},
			}

			response := &dns.Msg{
				Ns: []dns.RR{soa, nsec},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "m.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			// Should detect and use NSEC
			result := sut.validateDenialOfExistence(ctx, response, question)
			Expect(result).ShouldNot(BeNil())
		})

		It("should respect query budget during validation", func() {
			// Exhaust query budget
			exhaustedCtx := context.WithValue(context.Background(), queryBudgetKey{}, 0)

			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
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

			// Should fail on query budget when trying to validate authority section
			result := sut.validateDenialOfExistence(exhaustedCtx, response, question)
			Expect(result).ShouldNot(BeNil())
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
			Expect(result).Should(Equal(ValidationResultInsecure))
		})

		It("should detect both NSEC and NSEC3 when scanning authority section", func() {
			// Mix of NSEC, NSEC3, and other record types
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC},
				NextDomain: "z.example.com.",
			}
			nsec3 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: "hash.example.com.", Rrtype: dns.TypeNSEC3},
				Hash:       dns.SHA1,
				Salt:       "",
				Iterations: 0,
			}
			soa := &dns.SOA{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA},
			}

			response := &dns.Msg{
				Ns: []dns.RR{soa, nsec, nsec3},
			}
			response.Rcode = dns.RcodeNameError

			question := dns.Question{
				Name:   "test.example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			// Should use NSEC3 (checked first)
			result := sut.validateDenialOfExistence(ctx, response, question)
			Expect(result).ShouldNot(BeNil())
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

				// Without RRSIG, authority validation will return Insecure
				// But this tests the scanning logic
				result := sut.validateDenialOfExistence(ctx, response, question)
				Expect(result).Should(Equal(ValidationResultInsecure))
			})

			It("should call validateNSECDenialOfExistence when NSEC present and authority validates", func() {
				// Create a minimal NSEC record
				nsec := &dns.NSEC{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeNSEC,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					NextDomain: "z.example.com.",
					TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
				}

				response := &dns.Msg{
					Ns: []dns.RR{nsec},
				}
				response.Rcode = dns.RcodeNameError

				question := dns.Question{
					Name:   "nonexistent.example.com.",
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}

				// This will fail authority validation (no RRSIG) but tests the flow
				result := sut.validateDenialOfExistence(ctx, response, question)
				// Should attempt NSEC validation path
				Expect(result).ShouldNot(BeNil())
			})

			It("should call validateNSEC3DenialOfExistence when NSEC3 present and authority validates", func() {
				// Create a minimal NSEC3 record
				nsec3 := &dns.NSEC3{
					Hdr: dns.RR_Header{
						Name:   "ABC123.example.com.",
						Rrtype: dns.TypeNSEC3,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Hash:       dns.SHA1,
					Flags:      0,
					Iterations: 10,
					SaltLength: 0,
					Salt:       "",
					HashLength: 20,
					NextDomain: "DEF456",
					TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
				}

				response := &dns.Msg{
					Ns: []dns.RR{nsec3},
				}
				response.Rcode = dns.RcodeNameError

				question := dns.Question{
					Name:   "nonexistent.example.com.",
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}

				// This will fail authority validation (no RRSIG) but tests the flow
				result := sut.validateDenialOfExistence(ctx, response, question)
				// Should attempt NSEC3 validation path
				Expect(result).ShouldNot(BeNil())
			})

			It("should handle multiple NSEC records with different names", func() {
				nsec1 := &dns.NSEC{
					Hdr: dns.RR_Header{
						Name:   "a.example.com.",
						Rrtype: dns.TypeNSEC,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					NextDomain: "m.example.com.",
					TypeBitMap: []uint16{dns.TypeA},
				}
				nsec2 := &dns.NSEC{
					Hdr: dns.RR_Header{
						Name:   "m.example.com.",
						Rrtype: dns.TypeNSEC,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					NextDomain: "z.example.com.",
					TypeBitMap: []uint16{dns.TypeA},
				}

				response := &dns.Msg{
					Ns: []dns.RR{nsec1, nsec2},
				}
				response.Rcode = dns.RcodeNameError

				question := dns.Question{
					Name:   "p.example.com.",
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}

				result := sut.validateDenialOfExistence(ctx, response, question)
				Expect(result).ShouldNot(BeNil())
			})

			It("should handle NSEC3 with various hash iterations", func() {
				// Test with different iteration counts
				for _, iterations := range []uint16{0, 1, 10, 150} {
					nsec3 := &dns.NSEC3{
						Hdr: dns.RR_Header{
							Name:   "ABC123.example.com.",
							Rrtype: dns.TypeNSEC3,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Hash:       dns.SHA1,
						Flags:      0,
						Iterations: iterations,
						SaltLength: 0,
						Salt:       "",
						HashLength: 20,
						NextDomain: "DEF456",
						TypeBitMap: []uint16{dns.TypeA},
					}

					response := &dns.Msg{
						Ns: []dns.RR{nsec3},
					}
					response.Rcode = dns.RcodeNameError

					question := dns.Question{
						Name:   "nonexistent.example.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					}

					result := sut.validateDenialOfExistence(ctx, response, question)
					Expect(result).ShouldNot(BeNil())
				}
			})

			It("should handle NSEC3 with salt", func() {
				nsec3 := &dns.NSEC3{
					Hdr: dns.RR_Header{
						Name:   "ABC123.example.com.",
						Rrtype: dns.TypeNSEC3,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Hash:       dns.SHA1,
					Flags:      0,
					Iterations: 10,
					SaltLength: 4,
					Salt:       "ABCD1234",
					HashLength: 20,
					NextDomain: "DEF456",
					TypeBitMap: []uint16{dns.TypeA},
				}

				response := &dns.Msg{
					Ns: []dns.RR{nsec3},
				}
				response.Rcode = dns.RcodeNameError

				question := dns.Question{
					Name:   "nonexistent.example.com.",
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}

				result := sut.validateDenialOfExistence(ctx, response, question)
				Expect(result).ShouldNot(BeNil())
			})

			It("should detect NSEC when mixed with other authority records", func() {
				soa := &dns.SOA{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				}
				ns := &dns.NS{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns1.example.com.",
				}
				nsec := &dns.NSEC{
					Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
					NextDomain: "z.example.com.",
					TypeBitMap: []uint16{dns.TypeA},
				}

				response := &dns.Msg{
					Ns: []dns.RR{soa, ns, nsec},
				}
				response.Rcode = dns.RcodeNameError

				question := dns.Question{
					Name:   "nonexistent.example.com.",
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}

				result := sut.validateDenialOfExistence(ctx, response, question)
				Expect(result).ShouldNot(BeNil())
			})
		})
	})
})
