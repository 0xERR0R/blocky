package util

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/0xERR0R/blocky/log"

	"github.com/miekg/dns"
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

// SOA record timing defaults for negative responses (RFC 2308)
const (
	soaRefresh = 86400  // 24 hours
	soaRetry   = 7200   // 2 hours
	soaExpire  = 604800 // 7 days
)

// Obfuscate replaces all alphanumeric characters with * to obfuscate user sensitive data if LogPrivacy is enabled
func Obfuscate(in string) string {
	if LogPrivacy.Load() {
		return alphanumeric.ReplaceAllString(in, "*")
	}

	return in
}

// AnswerToString creates a user-friendly representation of an answer.
// The result is NOT obfuscated; callers that emit it to logs must wrap with Obfuscate.
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
			answers[i] = record.String()
		}
	}

	return strings.Join(answers, ", ")
}

// QuestionToString creates a user-friendly representation of a question
func QuestionToString(questions []dns.Question) string {
	result := make([]string, len(questions))
	for i, question := range questions {
		result[i] = fmt.Sprintf("%s (%s)", dns.TypeToString[question.Qtype], question.Name)
	}

	return Obfuscate(strings.Join(result, ", "))
}

// QuestionLogValuer defers QuestionToString formatting until a log record is
// actually emitted (implements slog.LogValuer). Use as:
//
//	slog.Any("question", util.QuestionLogValuer{Questions: req.Question})
type QuestionLogValuer struct {
	Questions []dns.Question
}

func (v QuestionLogValuer) LogValue() slog.Value {
	return slog.StringValue(QuestionToString(v.Questions))
}

// AnswerLogValuer defers (and obfuscates) AnswerToString formatting until a log
// record is actually emitted (implements slog.LogValuer), so the work is skipped
// entirely when the level is disabled. Use as:
//
//	slog.Any("answer", util.AnswerLogValuer{Answers: resp.Answer})
type AnswerLogValuer struct {
	Answers []dns.RR
}

func (v AnswerLogValuer) LogValue() slog.Value {
	return slog.StringValue(Obfuscate(AnswerToString(v.Answers)))
}

// DomainLogValuer defers (and obfuscates) a domain name until a log record is
// actually emitted (implements slog.LogValuer), so Obfuscate is skipped entirely
// when the level is disabled. Use as:
//
//	slog.Any("domain", util.DomainLogValuer{Domain: domain})
type DomainLogValuer struct {
	Domain string
}

func (v DomainLogValuer) LogValue() slog.Value {
	return slog.StringValue(Obfuscate(v.Domain))
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

	log.Log().Error("Using fallback for unsupported query type", slog.String("type", dns.TypeToString[question.Qtype]))

	rr, err := dns.NewRR(fmt.Sprintf("%s %d %s %s %s",
		question.Name, remainingTTL, "IN", dns.TypeToString[question.Qtype], ip))
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS RR for type %s: %w", dns.TypeToString[question.Qtype], err)
	}

	return rr, nil
}

// CreateHeader creates DNS header for passed question
func CreateHeader(question dns.Question, remainingTTL uint32) dns.RR_Header {
	return dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: remainingTTL}
}

// CreateSOAForNegativeResponse creates an SOA record for NXDOMAIN responses
// per RFC 2308. The TTL and MINTTL are both set to blockTTL to ensure
// proper negative caching behavior.
func CreateSOAForNegativeResponse(question dns.Question, blockTTL uint32) *dns.SOA {
	// Use the queried domain as the zone name
	zoneName := dns.Fqdn(question.Name)

	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zoneName,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    blockTTL,
		},
		Ns:      "blocky.local.",            // Name server
		Mbox:    "hostmaster.blocky.local.", // Mailbox (admin contact)
		Serial:  1,                          // Serial number
		Refresh: soaRefresh,                 // 24 hours
		Retry:   soaRetry,                   // 2 hours
		Expire:  soaExpire,                  // 7 days
		Minttl:  blockTTL,                   // Negative caching TTL (RFC 2308)
	}
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
		return nil, fmt.Errorf("failed to create DNS RR for domain '%s' (type %s): %w", domain, dnsType, err)
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
	ss := make([]kv, 0, len(in))

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

// LogOnError logs the message only if error is not nil, using the ctx-bound
// logger so request-scoped fields are included.
func LogOnError(ctx context.Context, message string, err error) {
	LogOnErrorWithEntry(log.FromCtx(ctx), message, err)
}

// LogOnErrorWithEntry logs the message only if error is not nil
func LogOnErrorWithEntry(logEntry *slog.Logger, message string, err error) {
	if err != nil {
		logEntry.Error(message, log.AttrError(err))
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

	return qType, qName
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

// ExtractRecords extracts all records of type T from a DNS message's Answer section
func ExtractRecords[T dns.RR](msg *dns.Msg) []T {
	var records []T
	for _, rr := range msg.Answer {
		if record, ok := rr.(T); ok {
			records = append(records, record)
		}
	}

	return records
}

// ExtractRecordsFromSlice extracts all records of type T from a DNS RR slice
func ExtractRecordsFromSlice[T dns.RR](rrs []dns.RR) []T {
	var records []T
	for _, rr := range rrs {
		if record, ok := rr.(T); ok {
			records = append(records, record)
		}
	}

	return records
}
