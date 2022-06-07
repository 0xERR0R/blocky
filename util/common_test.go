package util

import (
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
		ip := net.ParseIP("192.168.178.1")
		When("type A is provided", func() {
			question := dns.Question{
				Name:   "google.de",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
			answer, err := CreateAnswerFromQuestion(question, ip, 25)
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
			answer, err := CreateAnswerFromQuestion(question, ip, 25)
			Expect(err).Should(Succeed())
			It("should return AAAA record", func() {
				Expect(answer.String()).Should(Equal("google.de	25	IN	AAAA	192.168.178.1"))
			})
		})
		When("type NS is provided", func() {
			question := dns.Question{
				Name:   "google.de",
				Qtype:  dns.TypeNS,
				Qclass: dns.ClassINET,
			}
			answer, err := CreateAnswerFromQuestion(question, ip, 25)
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
			_, err := CreateAnswerFromQuestion(question, ip, 25)
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
			It("should log", func() {
				hook := test.NewGlobal()
				Log().AddHook(hook)
				defer hook.Reset()
				LogOnError("message ", err)
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
})
