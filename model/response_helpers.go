package model

import "github.com/miekg/dns"

// NewResponseWithReason creates a response with a DNS message that has SetReply called.
// This is used when you want to create a response that replies to the request,
// optionally with answer records.
func NewResponseWithReason(request *Request, rtype ResponseType, reason string) *Response {
	response := new(dns.Msg)
	response.SetReply(request.Req)

	return &Response{
		Res:    response,
		RType:  rtype,
		Reason: reason,
	}
}

// NewResponseWithAnswers creates a response with a DNS message that has SetReply called
// and the provided answer records added.
func NewResponseWithAnswers(request *Request, answers []dns.RR, rtype ResponseType, reason string) *Response {
	response := new(dns.Msg)
	response.SetReply(request.Req)
	response.Answer = answers

	return &Response{
		Res:    response,
		RType:  rtype,
		Reason: reason,
	}
}

// NewResponseWithRcode creates a response with a specific return code using SetRcode.
// This is typically used for empty responses with specific error codes.
func NewResponseWithRcode(request *Request, rcode int, rtype ResponseType, reason string) *Response {
	response := new(dns.Msg)
	response.SetRcode(request.Req, rcode)

	return &Response{
		Res:    response,
		RType:  rtype,
		Reason: reason,
	}
}

// NewEmptyResponse creates a response with just the Rcode field set (no SetReply or SetRcode).
// This is used for minimal responses where only the return code matters.
func NewEmptyResponse(request *Request, rcode int, rtype ResponseType, reason string) *Response {
	response := new(dns.Msg)
	response.Rcode = rcode

	return &Response{
		Res:    response,
		RType:  rtype,
		Reason: reason,
	}
}
