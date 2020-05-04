package helpertest

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/miekg/dns"
	"github.com/onsi/gomega/types"
)

// creates temp file with passed data
func TempFile(data string) *os.File {
	f, err := ioutil.TempFile("", "prefix")
	if err != nil {
		log.Fatal(err)
	}

	_, err = f.WriteString(data)
	if err != nil {
		log.Fatal(err)
	}

	return f
}

// creates temp http server with passed data
func TestServer(data string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := rw.Write([]byte(data))
		if err != nil {
			log.Fatal("can't write to buffer:", err)
		}
	}))
}

func DoGetRequest(url string, fn func(w http.ResponseWriter, r *http.Request)) (code int, body *bytes.Buffer) {
	r, _ := http.NewRequest("GET", url, nil)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(fn)

	handler.ServeHTTP(rr, r)

	return rr.Code, rr.Body
}

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

func (matcher *dnsRecordMatcher) Match(actual interface{}) (success bool, err error) {
	switch i := actual.(type) {
	case dns.RR:
		return matcher.matchSingle(i)
	case []dns.RR:
		return matcher.matchSingle(i[0])
	default:
		return false, fmt.Errorf("DNSRecord matcher expects an dns.RR or []dns.RR")
	}
}

func (matcher *dnsRecordMatcher) FailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected\n\t%s\nto contain\n\tdomain '%s', ttl '%d', type '%s', answer '%s'",
		actual, matcher.domain, matcher.TTL, dns.TypeToString[matcher.dnsType], matcher.answer)
}

func (matcher *dnsRecordMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected\n\t%s\n not to contain\n\tdomain '%s', ttl '%d', type '%s', answer '%s'",
		actual, matcher.domain, matcher.TTL, dns.TypeToString[matcher.dnsType], matcher.answer)
}
