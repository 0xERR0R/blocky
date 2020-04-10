package util

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
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

func CreateAnswerFromQuestion(question dns.Question, ip net.IP, remainingTTL uint32) (dns.RR, error) {
	return dns.NewRR(fmt.Sprintf("%s %d %s %s %s",
		question.Name, remainingTTL, "IN", dns.TypeToString[question.Qtype], ip))
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

func NewMsgWithAnswer(answer string) (*dns.Msg, error) {
	rr, err := dns.NewRR(answer)
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
