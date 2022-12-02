package helpertest

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/0xERR0R/blocky/log"

	"github.com/miekg/dns"
	"github.com/onsi/gomega/types"
)

// TempFile creates temp file with passed data
func TempFile(data string) *os.File {
	f, err := os.CreateTemp("", "prefix")
	if err != nil {
		log.Log().Fatal(err)
	}

	_, err = f.WriteString(data)
	if err != nil {
		log.Log().Fatal(err)
	}

	return f
}

// TestServer creates temp http server with passed data
func TestServer(data string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := rw.Write([]byte(data))
		if err != nil {
			log.Log().Fatal("can't write to buffer:", err)
		}
	}))
}

// DoGetRequest performs a GET request
func DoGetRequest(url string,
	fn func(w http.ResponseWriter, r *http.Request)) (*httptest.ResponseRecorder, *bytes.Buffer) {
	r, _ := http.NewRequest(http.MethodGet, url, nil)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(fn)

	handler.ServeHTTP(rr, r)

	return rr, rr.Body
}

// BeDNSRecord returns new dns matcher
func BeDNSRecord(domain string, dnsType uint16, ttl uint32, answer string) types.GomegaMatcher {
	return &dnsRecordMatcher{
		domain:  domain,
		dnsType: dnsType,
		TTL:     ttl,
		answer:  answer,
	}
}

type dnsRecordMatcher struct {
	domain  string
	dnsType uint16
	TTL     uint32
	answer  string
}

func (matcher *dnsRecordMatcher) matchSingle(rr dns.RR) (success bool, err error) {
	if (rr.Header().Name != matcher.domain) ||
		(rr.Header().Rrtype != matcher.dnsType) ||
		(matcher.TTL > 0 && (rr.Header().Ttl != matcher.TTL)) {
		return false, nil
	}

	switch v := rr.(type) {
	case *dns.A:
		return v.A.String() == matcher.answer, nil
	case *dns.AAAA:
		return v.AAAA.String() == matcher.answer, nil
	case *dns.PTR:
		return v.Ptr == matcher.answer, nil
	case *dns.MX:
		return v.Mx == matcher.answer, nil
	}

	return false, nil
}

// Match checks the DNS record
func (matcher *dnsRecordMatcher) Match(actual interface{}) (success bool, err error) {
	switch i := actual.(type) {
	case *dns.Msg:
		return matcher.Match(i.Answer)
	case dns.RR:
		return matcher.matchSingle(i)
	case []dns.RR:
		if len(i) == 1 {
			return matcher.matchSingle(i[0])
		}

		return false, fmt.Errorf("DNSRecord matcher expects []dns.RR with len == 1")
	default:
		return false, fmt.Errorf("DNSRecord matcher expects an dns.RR or []dns.RR")
	}
}

// FailureMessage generates a failure messge
func (matcher *dnsRecordMatcher) FailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected\n\t%s\n to contain\n\t domain '%s', ttl '%d', type '%s', answer '%s'",
		actual, matcher.domain, matcher.TTL, dns.TypeToString[matcher.dnsType], matcher.answer)
}

// NegatedFailureMessage creates negated message
func (matcher *dnsRecordMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected\n\t%s\n not to contain\n\t domain '%s', ttl '%d', type '%s', answer '%s'",
		actual, matcher.domain, matcher.TTL, dns.TypeToString[matcher.dnsType], matcher.answer)
}
