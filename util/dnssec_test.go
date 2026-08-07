package util

import (
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("DNSSEC utils", func() {
	Describe("StripDNSSECRecords", func() {
		var msg *dns.Msg

		// rr parses a record from its zone file presentation, failing the spec if it is invalid.
		rr := func(s string) dns.RR {
			record, err := dns.NewRR(s)
			Expect(err).Should(Succeed())

			return record
		}

		// types returns the RR types of the given records, to assert on a whole section at once.
		types := func(records []dns.RR) []uint16 {
			result := make([]uint16, 0, len(records))
			for _, record := range records {
				result = append(result, record.Header().Rrtype)
			}

			return result
		}

		BeforeEach(func() {
			msg = new(dns.Msg)
			msg.SetQuestion(exampleDomain+".", dns.TypeA)
		})

		When("the answer section is signed", func() {
			BeforeEach(func() {
				msg.Answer = []dns.RR{
					rr("example.com. 300 IN A 1.2.3.4"),
					rr("example.com. 300 IN RRSIG A 13 2 300 20260806185109 20260716185109 12345 example.com. c2lnbmF0dXJl"),
					rr("example.com. 300 IN A 5.6.7.8"),
				}
			})

			It("removes the signatures and keeps the answer", func() {
				Expect(StripDNSSECRecords(msg, dns.TypeA)).Should(BeTrue())
				Expect(types(msg.Answer)).Should(Equal([]uint16{dns.TypeA, dns.TypeA}))
			})
		})

		When("the response proves denial of existence", func() {
			It("removes an NSEC proof and keeps the SOA", func() {
				msg.Ns = []dns.RR{
					rr("example.com. 300 IN SOA ns.example.com. admin.example.com. 1 7200 3600 1209600 300"),
					rr("example.com. 300 IN NSEC www.example.com. A RRSIG NSEC"),
					rr("example.com. 300 IN RRSIG NSEC 13 2 300 20260806185109 20260716185109 12345 example.com. c2lnbmF0dXJl"),
				}

				Expect(StripDNSSECRecords(msg, dns.TypeA)).Should(BeTrue())
				Expect(types(msg.Ns)).Should(Equal([]uint16{dns.TypeSOA}))
			})

			It("removes an NSEC3 proof and keeps the SOA", func() {
				msg.Ns = []dns.RR{
					rr("example.com. 300 IN SOA ns.example.com. admin.example.com. 1 7200 3600 1209600 300"),
					rr("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.com. 300 IN NSEC3 1 0 12 aabbccdd 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG"),
				}

				Expect(StripDNSSECRecords(msg, dns.TypeA)).Should(BeTrue())
				Expect(types(msg.Ns)).Should(Equal([]uint16{dns.TypeSOA}))
			})
		})

		When("the response carries key material the query didn't ask for", func() {
			It("removes DNSKEY and DS records", func() {
				msg.Answer = []dns.RR{
					rr("example.com. 300 IN A 1.2.3.4"),
					rr("example.com. 3600 IN DNSKEY 256 3 13 a2V5"),
					rr("example.com. 3600 IN DS 12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
				}

				Expect(StripDNSSECRecords(msg, dns.TypeA)).Should(BeTrue())
				Expect(types(msg.Answer)).Should(Equal([]uint16{dns.TypeA}))
			})
		})

		When("the query explicitly asks for a DNSSEC type", func() {
			It("keeps the requested DNSKEY records but not the signatures over them", func() {
				msg.Answer = []dns.RR{
					rr("example.com. 3600 IN DNSKEY 256 3 13 a2V5"),
					rr("example.com. 3600 IN RRSIG DNSKEY 13 2 3600 20260806185109 20260716185109 12345 example.com. c2lnbmF0dXJl"),
				}

				Expect(StripDNSSECRecords(msg, dns.TypeDNSKEY)).Should(BeTrue())
				Expect(types(msg.Answer)).Should(Equal([]uint16{dns.TypeDNSKEY}))
			})

			It("keeps the requested DS records", func() {
				msg.Answer = []dns.RR{
					rr("example.com. 3600 IN DS 12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
				}

				Expect(StripDNSSECRecords(msg, dns.TypeDS)).Should(BeFalse())
				Expect(types(msg.Answer)).Should(Equal([]uint16{dns.TypeDS}))
			})

			It("keeps RRSIG records for an RRSIG query", func() {
				msg.Answer = []dns.RR{
					rr("example.com. 300 IN RRSIG A 13 2 300 20260806185109 20260716185109 12345 example.com. c2lnbmF0dXJl"),
				}

				Expect(StripDNSSECRecords(msg, dns.TypeRRSIG)).Should(BeFalse())
				Expect(types(msg.Answer)).Should(Equal([]uint16{dns.TypeRRSIG}))
			})

			It("keeps the requested types of every question", func() {
				msg.Answer = []dns.RR{
					rr("example.com. 3600 IN DNSKEY 256 3 13 a2V5"),
					rr("example.com. 3600 IN DS 12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
					rr("example.com. 300 IN RRSIG DS 13 2 3600 20260806185109 20260716185109 12345 example.com. c2lnbmF0dXJl"),
				}

				Expect(StripDNSSECRecords(msg, dns.TypeDNSKEY, dns.TypeDS)).Should(BeTrue())
				Expect(types(msg.Answer)).Should(Equal([]uint16{dns.TypeDNSKEY, dns.TypeDS}))
			})
		})

		When("the query is for ANY", func() {
			// RFC 3225 §3 includes the security records that match an ANY query whether or not the
			// DO bit was set
			It("keeps everything", func() {
				msg.Answer = []dns.RR{
					rr("example.com. 300 IN A 1.2.3.4"),
					rr("example.com. 300 IN RRSIG A 13 2 300 20260806185109 20260716185109 12345 example.com. c2lnbmF0dXJl"),
				}
				msg.Ns = []dns.RR{
					rr("example.com. 300 IN NSEC www.example.com. A RRSIG NSEC"),
				}

				Expect(StripDNSSECRecords(msg, dns.TypeANY)).Should(BeFalse())
				Expect(types(msg.Answer)).Should(Equal([]uint16{dns.TypeA, dns.TypeRRSIG}))
				Expect(types(msg.Ns)).Should(Equal([]uint16{dns.TypeNSEC}))
			})
		})

		It("strips every section and leaves other records in place", func() {
			msg.Answer = []dns.RR{
				rr("example.com. 300 IN A 1.2.3.4"),
				rr("example.com. 300 IN RRSIG A 13 2 300 20260806185109 20260716185109 12345 example.com. c2lnbmF0dXJl"),
			}
			msg.Ns = []dns.RR{
				rr("example.com. 300 IN NS ns.example.com."),
				rr("example.com. 300 IN RRSIG NS 13 2 300 20260806185109 20260716185109 12345 example.com. c2lnbmF0dXJl"),
			}
			msg.Extra = []dns.RR{
				rr("ns.example.com. 300 IN A 9.9.9.9"),
				rr("ns.example.com. 300 IN RRSIG A 13 3 300 20260806185109 20260716185109 12345 example.com. c2lnbmF0dXJl"),
			}
			msg.SetEdns0(4096, true)

			Expect(StripDNSSECRecords(msg, dns.TypeA)).Should(BeTrue())
			Expect(types(msg.Answer)).Should(Equal([]uint16{dns.TypeA}))
			Expect(types(msg.Ns)).Should(Equal([]uint16{dns.TypeNS}))
			Expect(types(msg.Extra)).Should(Equal([]uint16{dns.TypeA, dns.TypeOPT}))
			Expect(msg.IsEdns0()).ShouldNot(BeNil(), "the OPT record is not a DNSSEC record")
		})

		When("the response carries no DNSSEC records", func() {
			It("reports that nothing was removed and leaves the response untouched", func() {
				msg.Answer = []dns.RR{rr("example.com. 300 IN A 1.2.3.4")}

				Expect(StripDNSSECRecords(msg, dns.TypeA)).Should(BeFalse())
				Expect(types(msg.Answer)).Should(Equal([]uint16{dns.TypeA}))
			})
		})

		When("the message is nil", func() {
			It("reports that nothing was removed", func() {
				Expect(StripDNSSECRecords(nil, dns.TypeA)).Should(BeFalse())
			})
		})
	})
})
