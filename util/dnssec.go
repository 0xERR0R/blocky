package util

import (
	"slices"

	"github.com/miekg/dns"
)

// isDNSSECAuthRecordType reports whether rrType is one of the record types a security-aware
// resolver adds to a response solely so that the client can authenticate the rest of it
// (RFC 4034 §2-5, RFC 5155 §3).
//
// NSEC3PARAM, CDS and CDNSKEY are deliberately absent: they are ordinary zone data published by
// the zone owner, returned only when queried for, and never added to an answer as authentication
// material.
func isDNSSECAuthRecordType(rrType uint16) bool {
	switch rrType {
	case dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3:
		return true
	default:
		return false
	}
}

// StripDNSSECRecords removes the DNSSEC authentication records from every section of msg,
// except records whose type appears in requestedTypes. It reports whether anything was removed.
//
// RFC 4035 §3.2.1 requires this of the name server side of a security-aware recursive name
// server whenever the initiating query left the EDNS0 DO bit clear: it "MUST strip any
// authenticating DNSSEC RRs from the response but MUST NOT strip any DNSSEC RR types that the
// initiating query explicitly requested". requestedTypes carries the query's QTYPEs to implement
// that exception, so a client that does not validate still gets an answer to an explicit DNSKEY
// or DS query — just without the signatures over it.
//
// RFC 3225 §3 spells the exception out and extends it to QTYPE=ANY: "Security records that match
// an explicit SIG, KEY, NXT, or ANY query, or are part of the zone data for an AXFR or IXFR query,
// are included whether or not the DO bit was set." An ANY query therefore keeps everything. The
// AXFR/IXFR half does not apply here: blocky forwards queries to an upstream resolver and never
// serves zone transfers.
func StripDNSSECRecords(msg *dns.Msg, requestedTypes ...uint16) bool {
	if msg == nil || slices.Contains(requestedTypes, dns.TypeANY) {
		return false
	}

	removed := false

	for _, section := range []*[]dns.RR{&msg.Answer, &msg.Ns, &msg.Extra} {
		kept := slices.DeleteFunc(*section, func(rr dns.RR) bool {
			rrType := rr.Header().Rrtype

			return isDNSSECAuthRecordType(rrType) && !slices.Contains(requestedTypes, rrType)
		})

		if len(kept) != len(*section) {
			removed = true
		}

		*section = kept
	}

	return removed
}
