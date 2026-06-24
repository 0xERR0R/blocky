package resolver

import (
	"fmt"

	"github.com/miekg/dns"
)

// Helpers shared by the mock upstream servers (UDP/TCP, DoT, DoQ) to build
// answer functions and finalize replies, so the identical logic isn't copied
// per protocol.

// rrAnswerFn returns a mock answer function that replies with the given resource
// records (in dns.NewRR text form).
func rrAnswerFn(answers ...string) func(request *dns.Msg) *dns.Msg {
	return func(_ *dns.Msg) *dns.Msg {
		msg := new(dns.Msg)

		for _, a := range answers {
			rr, err := dns.NewRR(a)
			if err != nil {
				panic(fmt.Sprintf("can't create RR: %v", err))
			}

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
