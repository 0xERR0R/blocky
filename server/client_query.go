package server

import (
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

// clientQuery holds the properties of a query as the client itself sent it.
//
// The resolver chain mutates request.Req in place: ECS, DNSSEC and the upstream EDNS0 buffer floor
// may add or enlarge an OPT record the client never sent, and the DNSSEC resolver overwrites the DO
// bit because a validating resolver must always query upstream with DO set (RFC 4035 §3.2.1). The
// properties the response has to be normalized against are therefore captured before resolution
// starts, and applied afterwards by normalizeResponse.
type clientQuery struct {
	// maxResponseSize is the largest response the client accepts, derived from its own EDNS0
	// buffer size rather than the buffer the chain advertised upstream.
	maxResponseSize int

	// hadEdns0 records whether the query carried an OPT record.
	hadEdns0 bool

	// wantsDNSSEC is the state of the EDNS0 DO bit in the query.
	wantsDNSSEC bool

	// wantsAD records whether the client signalled interest in the AD bit, by setting AD in the
	// query (RFC 6840 §5.7) or by setting DO, which counts as the same signal (§5.8).
	wantsAD bool

	// recursionDesired is the state of the RD bit in the query.
	recursionDesired bool

	// qType is the QTYPE of the query, which drives the "explicitly requested" exception when
	// DNSSEC records are stripped. Zero when the query carries no question at all.
	qType uint16
}

func newClientQuery(request *model.Request) clientQuery {
	opt := request.Req.IsEdns0()
	do := opt != nil && opt.Do()

	// like every other resolver in the chain, only the first question is considered
	var qType uint16
	if len(request.Req.Question) > 0 {
		qType = request.Req.Question[0].Qtype
	}

	return clientQuery{
		maxResponseSize:  getMaxResponseSize(request),
		hadEdns0:         opt != nil,
		wantsDNSSEC:      do,
		wantsAD:          do || request.Req.AuthenticatedData,
		recursionDesired: request.Req.RecursionDesired,
		qType:            qType,
	}
}

// normalizeResponse adapts res to the query the client actually sent. It is the last step before
// the response goes on the wire.
func (q clientQuery) normalizeResponse(res *dns.Msg) {
	res.RecursionAvailable = q.recursionDesired

	if !q.wantsAD {
		// RFC 6840 §5.8: only report authenticated data to a client that asked for it by setting
		// DO or AD. The DNSSEC resolver sets AD on every response it validates, without knowing
		// what the client asked for.
		res.AuthenticatedData = false
	}

	if !q.wantsDNSSEC {
		// RFC 4035 §3.2.1: the DNSSEC records the chain requested upstream on the client's behalf
		// are for us to validate with, not for the client to receive. Stub resolvers may reject a
		// response carrying RRs they never asked for. Runs before Truncate, so stripping them can
		// keep a signed answer under the client's buffer size instead of truncating it.
		util.StripDNSSECRecords(res, q.qType)
	}

	if opt := res.IsEdns0(); opt != nil {
		// RFC 3225 §3: the DO bit of the query is copied into the response. The OPT record here is
		// the upstream's, which answered a query whose DO bit the chain may have set. Responses
		// blocky assembles itself carry no OPT and none is added here, so there is nothing to
		// mirror onto - notably cache hits, which are served from bytes packed without the OPT.
		opt.SetDo(q.wantsDNSSEC)
	}

	if !q.hadEdns0 {
		// don't return an OPT record to a client that didn't use EDNS0 (RFC 6891 section 7)
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
