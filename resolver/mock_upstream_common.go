package resolver

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Helpers shared by the mock upstream servers (UDP/TCP, DoT, DoQ) to build
// answer functions and finalize replies, so the identical logic isn't copied
// per protocol.

// panicOnError panics with message and err when err is not nil. The mock servers
// use it instead of util.FatalOnError: FatalOnError calls os.Exit, which skips
// Go's coverage-profile flush and leaves ginkgo's recursive coverage merge with
// a missing <package>/coverage.txt. Panicking turns the failure into a normal
// spec failure (or a GinkgoRecover-caught failure in a handler goroutine) while
// still letting the binary flush its coverage.
func panicOnError(message string, err error) {
	if err != nil {
		panic(fmt.Errorf("%s: %w", strings.TrimRight(strings.TrimSpace(message), ":"), err))
	}
}

// rrAnswerFn returns a mock answer function that replies with the given resource
// records (in dns.NewRR text form).
func rrAnswerFn(answers ...string) func(request *dns.Msg) *dns.Msg {
	return func(_ *dns.Msg) *dns.Msg {
		msg := new(dns.Msg)

		for _, a := range answers {
			rr, err := dns.NewRR(a)
			panicOnError("can't create RR", err)

			msg.Answer = append(msg.Answer, rr)
		}

		return msg
	}
}

// errorAnswerFn returns a mock answer function that replies with the given Rcode.
func errorAnswerFn(errorCode int) func(request *dns.Msg) *dns.Msg {
	return func(_ *dns.Msg) *dns.Msg {
		msg := new(dns.Msg)
		msg.Rcode = errorCode

		return msg
	}
}

// mockReply turns the response produced by a mock answer function into a reply to
// request. dns.Msg.SetReply resets Rcode to success, so a non-success Rcode set
// by the answer function is restored afterwards.
func mockReply(request, response *dns.Msg) *dns.Msg {
	rCode := response.Rcode
	response.SetReply(request)

	if rCode != 0 {
		response.Rcode = rCode
	}

	return response
}
