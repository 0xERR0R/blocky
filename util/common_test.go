package util

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	. "github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Common function tests", func() {
	Describe("Print DNS answer", func() {
		When("different types of DNS answers", func() {
			rr := make([]dns.RR, 0)
			rr = append(rr, &dns.A{A: net.ParseIP("127.0.0.1")})
			rr = append(rr, &dns.AAAA{AAAA: net.ParseIP("2001:0db8:85a3:08d3:1319:8a2e:0370:7344")})
			rr = append(rr, &dns.CNAME{Target: "cname"})
			rr = append(rr, &dns.PTR{Ptr: "ptr"})
			rr = append(rr, &dns.NS{Ns: "ns"})
			It("should print the answers", func() {
				answerToString := AnswerToString(rr)
				Expect(answerToString).Should(Equal("A (127.0.0.1), " +
					"AAAA (2001:db8:85a3:8d3:1319:8a2e:370:7344), CNAME (cname), PTR (ptr), \t0\tCLASS0\tNone\tns"))
			})
		})
	})

	Describe("print question", func() {
		When("question is provided", func() {
			question := dns.Question{
				Name:   "google.de",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
			It("should print the answers", func() {
				questionToString := QuestionToString([]dns.Question{question})
				Expect(questionToString).Should(Equal("A (google.de)"))
			})
		})
	})

	Describe("Extract domain from query", func() {
		When("Question is provided", func() {
			question := dns.Question{
				Name:   "google.de.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
			It("should extract only domain", func() {
				domain := ExtractDomain(question)
				Expect(domain).Should(Equal("google.de"))
			})
		})
	})

	Describe("Create new DNS message", func() {
		When("Question is provided", func() {
			question := "google.com."
			It("should create message", func() {
				msg := NewMsgWithQuestion(question, dns.Type(dns.TypeA))
				Expect(QuestionToString(msg.Question)).Should(Equal("A (google.com.)"))
			})
		})
		When("Answer is provided", func() {
			It("should create message", func() {
				msg, err := NewMsgWithAnswer("google.com", 25, dns.Type(dns.TypeA), "192.168.178.1")
				Expect(err).Should(Succeed())
				Expect(AnswerToString(msg.Answer)).Should(Equal("A (192.168.178.1)"))
			})
		})
		When("Answer is corrupt", func() {
			It("should throw an error", func() {
				_, err := NewMsgWithAnswer(strings.Repeat("a", 300), 25, dns.Type(dns.TypeA), "192.168.178.1")
				Expect(err).Should(HaveOccurred())
			})
		})
	})

	Describe("Create answer from question", func() {
		When("type A is provided", func() {
			question := dns.Question{
				Name:   "google.de",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
			answer, err := CreateAnswerFromQuestion(question, net.ParseIP("192.168.178.1"), 25)
			Expect(err).Should(Succeed())
			It("should return A record", func() {
				Expect(answer.String()).Should(Equal("google.de	25	IN	A	192.168.178.1"))
			})
		})
		When("type AAAA is provided", func() {
			question := dns.Question{
				Name:   "google.de",
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			}
			answer, err := CreateAnswerFromQuestion(question, net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), 25)
			Expect(err).Should(Succeed())
			It("should return AAAA record", func() {
				Expect(answer.String()).Should(Equal("google.de	25	IN	AAAA	2001:db8:85a3::8a2e:370:7334"))
			})
		})
		When("type NS is provided", func() {
			question := dns.Question{
				Name:   "google.de",
				Qtype:  dns.TypeNS,
				Qclass: dns.ClassINET,
			}
			answer, err := CreateAnswerFromQuestion(question, net.ParseIP("192.168.178.1"), 25)
			Expect(err).Should(Succeed())
			It("should return generic record as fallback", func() {
				Expect(answer.String()).Should(Equal("google.de.	25	IN	NS	192.168.178.1."))
			})
		})

		When("Invalid record is provided", func() {
			question := dns.Question{
				Name:   strings.Repeat("k", 99),
				Qtype:  dns.TypeNS,
				Qclass: dns.ClassINET,
			}
			_, err := CreateAnswerFromQuestion(question, net.ParseIP("192.168.178.1"), 25)
			It("should fail", func() {
				Expect(err).Should(HaveOccurred())
			})
		})
	})

	Describe("Sorted iteration over map", func() {
		When("Key-value map is provided", func() {
			m := make(map[string]int)
			m["x"] = 5
			m["a"] = 1
			m["m"] = 9
			It("should iterate in sorted order", func() {
				result := make([]string, 0)
				IterateValueSorted(m, func(s string, i int) {
					result = append(result, fmt.Sprintf("%s-%d", s, i))
				})
				Expect(strings.Join(result, ";")).Should(Equal("m-9;x-5;a-1"))
			})
		})
	})

	Describe("Logging functions", func() {
		When("LogOnError is called with error", func() {
			err := errors.New("test")
			It("should log", func(ctx context.Context) {
				hook := test.NewGlobal()
				Log().AddHook(hook)
				defer hook.Reset()
				LogOnError(ctx, "message ", err)
				Expect(hook.LastEntry().Message).Should(Equal("message test"))
			})
		})

		When("LogOnErrorWithEntry is called with error", func() {
			err := errors.New("test")
			It("should log", func() {
				hook := test.NewGlobal()
				Log().AddHook(hook)
				defer hook.Reset()
				logger, hook := test.NewNullLogger()
				entry := logrus.NewEntry(logger)
				LogOnErrorWithEntry(entry, "message ", err)
				Expect(hook.LastEntry().Message).Should(Equal("message test"))
			})
		})

		When("FatalOnError is called with error", func() {
			err := errors.New("test")
			It("should log and exit", func() {
				hook := test.NewGlobal()
				Log().AddHook(hook)
				fatal := false
				Log().ExitFunc = func(int) { fatal = true }
				defer func() {
					Log().ExitFunc = nil
				}()
				FatalOnError("message ", err)
				Expect(hook.LastEntry().Message).Should(Equal("message test"))
				Expect(fatal).Should(BeTrue())
			})
		})
	})

	Describe("Domain cache key generate/extract", func() {
		It("should works", func() {
			cacheKey := GenerateCacheKey(dns.Type(dns.TypeA), "example.com")
			qType, qName := ExtractCacheKey(cacheKey)
			Expect(qType).Should(Equal(dns.Type(dns.TypeA)))
			Expect(qName).Should(Equal("example.com"))
		})
	})

	Describe("CIDR contains IP", func() {
		It("should return true if CIDR (10.43.8.64 - 10.43.8.79) contains the IP", func() {
			c := CidrContainsIP("10.43.8.67/28", net.ParseIP("10.43.8.64"))
			Expect(c).Should(BeTrue())
		})
		It("should return false if CIDR (10.43.8.64 - 10.43.8.79) doesn't contain the IP", func() {
			c := CidrContainsIP("10.43.8.67/28", net.ParseIP("10.43.8.63"))
			Expect(c).Should(BeFalse())
		})
		It("should return false if CIDR is wrong", func() {
			c := CidrContainsIP("10.43.8.67", net.ParseIP("10.43.8.63"))
			Expect(c).Should(BeFalse())
		})
	})

	Describe("Client name matches group name", func() {
		It("should return true if client name matches with wildcard", func() {
			c := ClientNameMatchesGroupName("group*", "group-test")
			Expect(c).Should(BeTrue())
		})
		It("should return false if client name doesn't match with wildcard", func() {
			c := ClientNameMatchesGroupName("group*", "abc")
			Expect(c).Should(BeFalse())
		})
		It("should return true if client name matches with range wildcard", func() {
			c := ClientNameMatchesGroupName("group[1-3]", "group1")
			Expect(c).Should(BeTrue())
		})
		It("should return false if client name doesn't match with range wildcard", func() {
			c := ClientNameMatchesGroupName("group[1-3]", "group4")
			Expect(c).Should(BeFalse())
		})
	})

	Describe("CreateSOAForNegativeResponse", func() {
		When("A valid question and blockTTL are provided", func() {
			question := dns.Question{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
			blockTTL := uint32(3600)

			It("should create SOA with correct TTL and MINTTL", func() {
				soa := CreateSOAForNegativeResponse(question, blockTTL)

				Expect(soa).ShouldNot(BeNil())
				Expect(soa.Header().Ttl).Should(Equal(blockTTL))
				Expect(soa.Minttl).Should(Equal(blockTTL))
			})

			It("should create SOA with correct domain name", func() {
				soa := CreateSOAForNegativeResponse(question, blockTTL)

				Expect(soa.Header().Name).Should(Equal("example.com."))
				Expect(soa.Header().Rrtype).Should(Equal(dns.TypeSOA))
			})

			It("should create SOA with proper nameserver and mailbox", func() {
				soa := CreateSOAForNegativeResponse(question, blockTTL)

				Expect(soa.Ns).Should(Equal("blocky.local."))
				Expect(soa.Mbox).Should(Equal("hostmaster.blocky.local."))
			})

			It("should create SOA with standard timing values", func() {
				soa := CreateSOAForNegativeResponse(question, blockTTL)

				Expect(soa.Serial).Should(Equal(uint32(1)))
				Expect(soa.Refresh).Should(Equal(uint32(86400))) // 24 hours
				Expect(soa.Retry).Should(Equal(uint32(7200)))    // 2 hours
				Expect(soa.Expire).Should(Equal(uint32(604800))) // 7 days
			})
		})

		When("Domain name is not FQDN", func() {
			question := dns.Question{
				Name:   "example.com", // Without trailing dot
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			It("should handle non-FQDN domain names", func() {
				soa := CreateSOAForNegativeResponse(question, 60)

				Expect(soa.Header().Name).Should(Equal("example.com.")) // Should add trailing dot
			})
		})

		When("Different TTL values are provided", func() {
			question := dns.Question{
				Name:   "test.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			It("should respect blockTTL of 60 seconds", func() {
				soa := CreateSOAForNegativeResponse(question, 60)

				Expect(soa.Header().Ttl).Should(Equal(uint32(60)))
				Expect(soa.Minttl).Should(Equal(uint32(60)))
			})

			It("should respect blockTTL of 7200 seconds", func() {
				soa := CreateSOAForNegativeResponse(question, 7200)

				Expect(soa.Header().Ttl).Should(Equal(uint32(7200)))
				Expect(soa.Minttl).Should(Equal(uint32(7200)))
			})
		})
	})

	Describe("ExtractRecords", func() {
		When("DNS message contains mixed record types", func() {
			var msg *dns.Msg

			BeforeEach(func() {
				msg = new(dns.Msg)

				aQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
				aaaaQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
				cnameQuestion := dns.Question{Name: "alias.com.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET}
				nsQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}

				aRecord1 := &dns.A{
					Hdr: CreateHeader(aQuestion, 300),
					A:   net.ParseIP("192.168.1.1"),
				}
				aaaaRecord := &dns.AAAA{
					Hdr:  CreateHeader(aaaaQuestion, 300),
					AAAA: net.ParseIP("2001:db8::1"),
				}
				aRecord2 := &dns.A{
					Hdr: CreateHeader(aQuestion, 300),
					A:   net.ParseIP("192.168.1.2"),
				}
				cnameRecord := &dns.CNAME{
					Hdr:    CreateHeader(cnameQuestion, 300),
					Target: "example.com.",
				}
				nsRecord := &dns.NS{
					Hdr: CreateHeader(nsQuestion, 300),
					Ns:  "ns1.example.com.",
				}

				msg.Answer = []dns.RR{aRecord1, aaaaRecord, aRecord2, cnameRecord, nsRecord}
			})

			It("should extract all A records", func() {
				aRecords := ExtractRecords[*dns.A](msg)

				Expect(aRecords).Should(HaveLen(2))
				Expect(aRecords[0].A.String()).Should(Equal("192.168.1.1"))
				Expect(aRecords[1].A.String()).Should(Equal("192.168.1.2"))
			})

			It("should extract all AAAA records", func() {
				aaaaRecords := ExtractRecords[*dns.AAAA](msg)

				Expect(aaaaRecords).Should(HaveLen(1))
				Expect(aaaaRecords[0].AAAA.String()).Should(Equal("2001:db8::1"))
			})

			It("should extract all CNAME records", func() {
				cnameRecords := ExtractRecords[*dns.CNAME](msg)

				Expect(cnameRecords).Should(HaveLen(1))
				Expect(cnameRecords[0].Target).Should(Equal("example.com."))
			})

			It("should extract all NS records", func() {
				nsRecords := ExtractRecords[*dns.NS](msg)

				Expect(nsRecords).Should(HaveLen(1))
				Expect(nsRecords[0].Ns).Should(Equal("ns1.example.com."))
			})
		})

		When("DNS message has no matching records", func() {
			var msg *dns.Msg

			BeforeEach(func() {
				msg = new(dns.Msg)

				aQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
				cnameQuestion := dns.Question{Name: "alias.com.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET}

				msg.Answer = []dns.RR{
					&dns.A{
						Hdr: CreateHeader(aQuestion, 300),
						A:   net.ParseIP("192.168.1.1"),
					},
					&dns.CNAME{
						Hdr:    CreateHeader(cnameQuestion, 300),
						Target: "example.com.",
					},
				}
			})

			It("should return empty slice for MX records", func() {
				mxRecords := ExtractRecords[*dns.MX](msg)

				Expect(mxRecords).Should(BeEmpty())
			})

			It("should return empty slice for TXT records", func() {
				txtRecords := ExtractRecords[*dns.TXT](msg)

				Expect(txtRecords).Should(BeEmpty())
			})
		})

		When("DNS message has empty answer section", func() {
			var msg *dns.Msg

			BeforeEach(func() {
				msg = new(dns.Msg)
				msg.Answer = []dns.RR{}
			})

			It("should return empty slice for A records", func() {
				aRecords := ExtractRecords[*dns.A](msg)

				Expect(aRecords).Should(BeEmpty())
			})
		})

		When("DNS message contains only matching record type", func() {
			var msg *dns.Msg

			BeforeEach(func() {
				msg = new(dns.Msg)

				aQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

				msg.Answer = []dns.RR{
					&dns.A{
						Hdr: CreateHeader(aQuestion, 300),
						A:   net.ParseIP("192.168.1.1"),
					},
					&dns.A{
						Hdr: CreateHeader(aQuestion, 300),
						A:   net.ParseIP("192.168.1.2"),
					},
					&dns.A{
						Hdr: CreateHeader(aQuestion, 300),
						A:   net.ParseIP("192.168.1.3"),
					},
				}
			})

			It("should extract all A records", func() {
				aRecords := ExtractRecords[*dns.A](msg)

				Expect(aRecords).Should(HaveLen(3))
				Expect(aRecords[0].A.String()).Should(Equal("192.168.1.1"))
				Expect(aRecords[1].A.String()).Should(Equal("192.168.1.2"))
				Expect(aRecords[2].A.String()).Should(Equal("192.168.1.3"))
			})
		})

		When("DNS message contains SOA and PTR records", func() {
			var msg *dns.Msg

			BeforeEach(func() {
				msg = new(dns.Msg)

				soaQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeSOA, Qclass: dns.ClassINET}
				ptrQuestion := dns.Question{Name: "1.1.168.192.in-addr.arpa.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}

				msg.Answer = []dns.RR{
					&dns.SOA{
						Hdr:     CreateHeader(soaQuestion, 3600),
						Ns:      "ns1.example.com.",
						Mbox:    "admin.example.com.",
						Serial:  2024010101,
						Refresh: 86400,
						Retry:   7200,
						Expire:  604800,
						Minttl:  3600,
					},
					&dns.PTR{
						Hdr: CreateHeader(ptrQuestion, 300),
						Ptr: "example.com.",
					},
				}
			})

			It("should extract SOA record", func() {
				soaRecords := ExtractRecords[*dns.SOA](msg)

				Expect(soaRecords).Should(HaveLen(1))
				Expect(soaRecords[0].Ns).Should(Equal("ns1.example.com."))
				Expect(soaRecords[0].Serial).Should(Equal(uint32(2024010101)))
			})

			It("should extract PTR record", func() {
				ptrRecords := ExtractRecords[*dns.PTR](msg)

				Expect(ptrRecords).Should(HaveLen(1))
				Expect(ptrRecords[0].Ptr).Should(Equal("example.com."))
			})
		})
	})

	Describe("ExtractRecordsFromSlice", func() {
		When("RR slice contains mixed record types", func() {
			var rrs []dns.RR

			BeforeEach(func() {
				aQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
				aaaaQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
				cnameQuestion := dns.Question{Name: "alias.com.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET}
				nsQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}

				rrs = []dns.RR{
					&dns.A{
						Hdr: CreateHeader(aQuestion, 300),
						A:   net.ParseIP("192.168.1.1"),
					},
					&dns.AAAA{
						Hdr:  CreateHeader(aaaaQuestion, 300),
						AAAA: net.ParseIP("2001:db8::1"),
					},
					&dns.A{
						Hdr: CreateHeader(aQuestion, 300),
						A:   net.ParseIP("192.168.1.2"),
					},
					&dns.CNAME{
						Hdr:    CreateHeader(cnameQuestion, 300),
						Target: "example.com.",
					},
					&dns.NS{
						Hdr: CreateHeader(nsQuestion, 300),
						Ns:  "ns1.example.com.",
					},
				}
			})

			It("should extract all A records", func() {
				aRecords := ExtractRecordsFromSlice[*dns.A](rrs)

				Expect(aRecords).Should(HaveLen(2))
				Expect(aRecords[0].A.String()).Should(Equal("192.168.1.1"))
				Expect(aRecords[1].A.String()).Should(Equal("192.168.1.2"))
			})

			It("should extract all AAAA records", func() {
				aaaaRecords := ExtractRecordsFromSlice[*dns.AAAA](rrs)

				Expect(aaaaRecords).Should(HaveLen(1))
				Expect(aaaaRecords[0].AAAA.String()).Should(Equal("2001:db8::1"))
			})

			It("should extract all CNAME records", func() {
				cnameRecords := ExtractRecordsFromSlice[*dns.CNAME](rrs)

				Expect(cnameRecords).Should(HaveLen(1))
				Expect(cnameRecords[0].Target).Should(Equal("example.com."))
			})

			It("should extract all NS records", func() {
				nsRecords := ExtractRecordsFromSlice[*dns.NS](rrs)

				Expect(nsRecords).Should(HaveLen(1))
				Expect(nsRecords[0].Ns).Should(Equal("ns1.example.com."))
			})
		})

		When("RR slice has no matching records", func() {
			var rrs []dns.RR

			BeforeEach(func() {
				aQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
				cnameQuestion := dns.Question{Name: "alias.com.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET}

				rrs = []dns.RR{
					&dns.A{
						Hdr: CreateHeader(aQuestion, 300),
						A:   net.ParseIP("192.168.1.1"),
					},
					&dns.CNAME{
						Hdr:    CreateHeader(cnameQuestion, 300),
						Target: "example.com.",
					},
				}
			})

			It("should return empty slice for MX records", func() {
				mxRecords := ExtractRecordsFromSlice[*dns.MX](rrs)

				Expect(mxRecords).Should(BeEmpty())
			})

			It("should return empty slice for TXT records", func() {
				txtRecords := ExtractRecordsFromSlice[*dns.TXT](rrs)

				Expect(txtRecords).Should(BeEmpty())
			})
		})

		When("RR slice is empty", func() {
			var rrs []dns.RR

			BeforeEach(func() {
				rrs = []dns.RR{}
			})

			It("should return empty slice for A records", func() {
				aRecords := ExtractRecordsFromSlice[*dns.A](rrs)

				Expect(aRecords).Should(BeEmpty())
			})
		})

		When("RR slice contains only matching record type", func() {
			var rrs []dns.RR

			BeforeEach(func() {
				aaaaQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}

				rrs = []dns.RR{
					&dns.AAAA{
						Hdr:  CreateHeader(aaaaQuestion, 300),
						AAAA: net.ParseIP("2001:db8::1"),
					},
					&dns.AAAA{
						Hdr:  CreateHeader(aaaaQuestion, 300),
						AAAA: net.ParseIP("2001:db8::2"),
					},
					&dns.AAAA{
						Hdr:  CreateHeader(aaaaQuestion, 300),
						AAAA: net.ParseIP("2001:db8::3"),
					},
				}
			})

			It("should extract all AAAA records", func() {
				aaaaRecords := ExtractRecordsFromSlice[*dns.AAAA](rrs)

				Expect(aaaaRecords).Should(HaveLen(3))
				Expect(aaaaRecords[0].AAAA.String()).Should(Equal("2001:db8::1"))
				Expect(aaaaRecords[1].AAAA.String()).Should(Equal("2001:db8::2"))
				Expect(aaaaRecords[2].AAAA.String()).Should(Equal("2001:db8::3"))
			})
		})

		When("RR slice contains TXT and MX records", func() {
			var rrs []dns.RR

			BeforeEach(func() {
				txtQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}
				mxQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeMX, Qclass: dns.ClassINET}

				rrs = []dns.RR{
					&dns.TXT{
						Hdr: CreateHeader(txtQuestion, 300),
						Txt: []string{"v=spf1 include:_spf.example.com ~all"},
					},
					&dns.MX{
						Hdr:        CreateHeader(mxQuestion, 300),
						Preference: 10,
						Mx:         "mail.example.com.",
					},
					&dns.TXT{
						Hdr: CreateHeader(txtQuestion, 300),
						Txt: []string{"google-site-verification=12345"},
					},
				}
			})

			It("should extract all TXT records", func() {
				txtRecords := ExtractRecordsFromSlice[*dns.TXT](rrs)

				Expect(txtRecords).Should(HaveLen(2))
				Expect(txtRecords[0].Txt).Should(Equal([]string{"v=spf1 include:_spf.example.com ~all"}))
				Expect(txtRecords[1].Txt).Should(Equal([]string{"google-site-verification=12345"}))
			})

			It("should extract all MX records", func() {
				mxRecords := ExtractRecordsFromSlice[*dns.MX](rrs)

				Expect(mxRecords).Should(HaveLen(1))
				Expect(mxRecords[0].Preference).Should(Equal(uint16(10)))
				Expect(mxRecords[0].Mx).Should(Equal("mail.example.com."))
			})
		})

		When("RR slice is nil", func() {
			var rrs []dns.RR

			BeforeEach(func() {
				rrs = nil
			})

			It("should return empty slice for A records", func() {
				aRecords := ExtractRecordsFromSlice[*dns.A](rrs)

				Expect(aRecords).Should(BeEmpty())
			})
		})
	})
})
