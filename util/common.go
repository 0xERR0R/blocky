package util

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

func AnswerToString(answer []dns.RR) string {
	answers := make([]string, len(answer))

	for i, record := range answer {
		switch v := record.(type) {
		case *dns.A:
			answers[i] = fmt.Sprintf("A (%s)", v.A)
		case *dns.AAAA:
			answers[i] = fmt.Sprintf("AAAA (%s)", v.AAAA)
		case *dns.CNAME:
			answers[i] = fmt.Sprintf("CNAME (%s)", v.Target)
		case *dns.PTR:
			answers[i] = fmt.Sprintf("PTR (%s)", v.Ptr)
		default:
			answers[i] = fmt.Sprint(record)
		}
	}

	return strings.Join(answers, ", ")
}

func QuestionToString(questions []dns.Question) string {
	result := make([]string, len(questions))
	for i, question := range questions {
		result[i] = fmt.Sprintf("%s (%s)", dns.TypeToString[question.Qtype], question.Name)
	}

	return strings.Join(result, ", ")
}

func CreateAnswerFromQuestion(question dns.Question, ip net.IP, remainingTTL uint32) dns.RR {
	h := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: remainingTTL}

	switch question.Qtype {
	case dns.TypeA:
		a := new(dns.A)
		a.A = ip
		a.Hdr = h

		return a
	case dns.TypeAAAA:
		a := new(dns.AAAA)
		a.AAAA = ip
		a.Hdr = h

		return a
	}

	log.Errorf("Using fallback for unsupported query type %s", dns.TypeToString[question.Qtype])

	rr, err := dns.NewRR(fmt.Sprintf("%s %d %s %s %s",
		question.Name, remainingTTL, "IN", dns.TypeToString[question.Qtype], ip))

	if err != nil {
		log.Errorf("Can't create fallback for: %s %d %s %s %s",
			question.Name, remainingTTL, "IN", dns.TypeToString[question.Qtype], ip)
	}

	return rr
}

func ExtractDomain(question dns.Question) string {
	return ExtractDomainOnly(question.Name)
}

func ExtractDomainOnly(in string) string {
	return strings.TrimSuffix(strings.ToLower(in), ".")
}

func NewMsgWithQuestion(question string, mType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(question, mType)

	return msg
}
func NewMsgWithAnswer(domain string, ttl uint, dnsType uint16, address string) (*dns.Msg, error) {
	rr, err := dns.NewRR(fmt.Sprintf("%s\t%d\tIN\t%s\t%s", domain, ttl, dns.TypeToString[dnsType], address))
	if err != nil {
		return nil, err
	}

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{rr}

	return msg, nil
}

type kv struct {
	key   string
	value int
}

func IterateValueSorted(in map[string]int, fn func(string, int)) {
	ss := make([]kv, 0)

	for k, v := range in {
		ss = append(ss, kv{k, v})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].value > ss[j].value || (ss[i].value == ss[j].value && ss[i].key > ss[j].key)
	})

	for _, kv := range ss {
		fn(kv.key, kv.value)
	}
}
