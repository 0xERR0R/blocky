package util

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func qTypeToString() func(uint16) string {
	innerMap := map[uint16]string{
		dns.TypeA:     "A",
		dns.TypeAAAA:  "AAAA",
		dns.TypeCNAME: "CNAME",
		dns.TypePTR:   "PTR",
		dns.TypeMX:    "MX",
	}

	return func(key uint16) string {
		return innerMap[key]
	}
}

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
		result[i] = fmt.Sprintf("%s (%s)", qTypeToString()(question.Qtype), question.Name)
	}

	return strings.Join(result, ", ")
}

func CreateAnswerFromQuestion(question dns.Question, ip net.IP, remainingTTL uint32) (dns.RR, error) {
	return dns.NewRR(fmt.Sprintf("%s %d %s %s %s", question.Name, remainingTTL, "IN", qTypeToString()(question.Qtype), ip))
}

func ExtractDomain(question dns.Question) string {
	return strings.TrimSuffix(strings.ToLower(question.Name), ".")
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
