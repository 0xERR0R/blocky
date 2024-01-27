package util

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/0xERR0R/blocky/log"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

//nolint:gochecknoglobals
var (
	// To avoid making this package depend on config, we use a global
	// that is set at config load.
	// Ideally we'd move the obfuscate code somewhere else (maybe into `log`),
	// but that would require also moving all its dependencies.
	// This is good enough for now.
	LogPrivacy atomic.Bool

	alphanumeric = regexp.MustCompile("[a-zA-Z0-9]")
)

// Obfuscate replaces all alphanumeric characters with * to obfuscate user sensitive data if LogPrivacy is enabled
func Obfuscate(in string) string {
	if LogPrivacy.Load() {
		return alphanumeric.ReplaceAllString(in, "*")
	}

	return in
}

// AnswerToString creates a user-friendly representation of an answer
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
			answers[i] = fmt.Sprint(record.String())
		}
	}

	return Obfuscate(strings.Join(answers, ", "))
}

// QuestionToString creates a user-friendly representation of a question
func QuestionToString(questions []dns.Question) string {
	result := make([]string, len(questions))
	for i, question := range questions {
		result[i] = fmt.Sprintf("%s (%s)", dns.TypeToString[question.Qtype], question.Name)
	}

	return Obfuscate(strings.Join(result, ", "))
}

// CreateAnswerFromQuestion creates new answer from a question
func CreateAnswerFromQuestion(question dns.Question, ip net.IP, remainingTTL uint32) (dns.RR, error) {
	h := CreateHeader(question, remainingTTL)

	switch question.Qtype {
	case dns.TypeA:
		a := new(dns.A)
		a.A = ip
		a.Hdr = h

		return a, nil
	case dns.TypeAAAA:
		a := new(dns.AAAA)
		a.AAAA = ip
		a.Hdr = h

		return a, nil
	}

	log.Log().Errorf("Using fallback for unsupported query type %s", dns.TypeToString[question.Qtype])

	return dns.NewRR(fmt.Sprintf("%s %d %s %s %s",
		question.Name, remainingTTL, "IN", dns.TypeToString[question.Qtype], ip))
}

// CreateHeader creates DNS header for passed question
func CreateHeader(question dns.Question, remainingTTL uint32) dns.RR_Header {
	return dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: remainingTTL}
}

// ExtractDomain returns domain string from the question
func ExtractDomain(question dns.Question) string {
	return ExtractDomainOnly(question.Name)
}

// ExtractDomainOnly extracts domain from the DNS query
func ExtractDomainOnly(in string) string {
	return strings.TrimSuffix(strings.ToLower(in), ".")
}

// NewMsgWithQuestion creates new DNS message with question
func NewMsgWithQuestion(question string, qType dns.Type) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(question), uint16(qType))

	return msg
}

// NewMsgWithAnswer creates new DNS message with answer
func NewMsgWithAnswer(domain string, ttl uint, dnsType dns.Type, address string) (*dns.Msg, error) {
	rr, err := dns.NewRR(fmt.Sprintf("%s\t%d\tIN\t%s\t%s", domain, ttl, dnsType, address))
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

// IterateValueSorted iterates over maps value in a sorted order and applies the passed function
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

// LogOnError logs the message only if error is not nil
func LogOnError(ctx context.Context, message string, err error) {
	if err != nil {
		log.FromCtx(ctx).Error(message, err)
	}
}

// LogOnErrorWithEntry logs the message only if error is not nil
func LogOnErrorWithEntry(logEntry *logrus.Entry, message string, err error) {
	if err != nil {
		logEntry.Error(message, err)
	}
}

// FatalOnError logs the message only if error is not nil and exits the program execution
func FatalOnError(message string, err error) {
	if err != nil {
		logger := log.Log()

		// Make sure the error is printend even if the log has been silenced
		if logger.Out == io.Discard {
			log.ConfigureLogger(logger, log.DefaultConfig())
		}

		logger.Fatal(message, err)
	}
}

// GenerateCacheKey return cacheKey by query type/domain
func GenerateCacheKey(qType dns.Type, qName string) string {
	const qTypeLength = 2
	b := make([]byte, qTypeLength+len(qName))

	binary.BigEndian.PutUint16(b, uint16(qType))
	copy(b[2:], strings.ToLower(qName))

	return string(b)
}

// ExtractCacheKey return query type/domain from cacheKey
func ExtractCacheKey(key string) (qType dns.Type, qName string) {
	b := []byte(key)

	qType = dns.Type(binary.BigEndian.Uint16(b))
	qName = string(b[2:])

	return
}

// CidrContainsIP checks if CIDR contains a single IP
func CidrContainsIP(cidr string, ip net.IP) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	return ipnet.Contains(ip)
}

// ClientNameMatchesGroupName checks if a group with optional wildcards contains a client name
func ClientNameMatchesGroupName(group, clientName string) bool {
	match, _ := filepath.Match(strings.ToLower(group), strings.ToLower(clientName))

	return match
}
