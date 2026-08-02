package server

import (
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

// clientQuery holds the properties of a query as the client itself sent it.
//
// The resolver chain mutates request.Req in place: ECS, DNSSEC and the upstream EDNS0 buffer floor
// may add or enlarge an OPT record the client never sent. The properties the response has to be
// normalized against are therefore captured before resolution starts, and applied afterwards by
// normalizeResponse.
type clientQuery struct {
	// maxResponseSize is the largest response the client accepts, derived from its own EDNS0
	// buffer size rather than the buffer the chain advertised upstream.
	maxResponseSize int

	// hadEdns0 records whether the query carried an OPT record.
	hadEdns0 bool

	// recursionDesired is the state of the RD bit in the query.
	recursionDesired bool
}

func newClientQuery(request *model.Request) clientQuery {
	return clientQuery{
		maxResponseSize:  getMaxResponseSize(request),
		hadEdns0:         request.Req.IsEdns0() != nil,
		recursionDesired: request.Req.RecursionDesired,
	}
}

// normalizeResponse adapts res to the query the client actually sent. It is the last step before
// the response goes on the wire.
func (q clientQuery) normalizeResponse(res *dns.Msg) {
	res.RecursionAvailable = q.recursionDesired

	if !q.hadEdns0 {
		// don't return an OPT record to a client that didn't use EDNS0 (RFC 6891 section 6.1.1)
		util.RemoveEdns0Record(res)
	}

	// truncate if necessary; Truncate also disables compression when the message already fits
	// uncompressed and enables it when compression is needed to fit, so we let it decide rather
	// than forcing Compress=true and paying a compression-map alloc + packing on every response.
	res.Truncate(q.maxResponseSize)
}

// For TCP returns 64k
// For UDP returns EDNS UDP size or if not present, 512
func getMaxResponseSize(req *model.Request) int {
	if req.Protocol == model.RequestProtocolTCP {
		return dns.MaxMsgSize
	}

	edns := req.Req.IsEdns0()
	if edns != nil && edns.UDPSize() > 0 {
		return int(edns.UDPSize())
	}

	return dns.MinMsgSize
}
