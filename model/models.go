package model

//go:generate go tool go-enum -f=$GOFILE --marshal --names
import (
	"net"
	"time"

	"github.com/miekg/dns"
)

// ResponseType represents the type of the response ENUM(
// RESOLVED // the response was resolved by the external upstream resolver
// CACHED // the response was resolved from cache
// BLOCKED // the query was blocked
// CONDITIONAL // the query was resolved by the conditional upstream resolver
// CUSTOMDNS // the query was resolved by a custom rule
// HOSTSFILE // the query was resolved by looking up the hosts file
// FILTERED // the query was filtered by query type
// NOTFQDN // the query was filtered as it is not fqdn conform
// SPECIAL // the query was resolved by the special use domain name resolver
// SYNTHESIZED // the response was synthesized by DNS64
// REBIND // the answer was blocked by the DNS rebinding protection
// BOGUS // the answer failed DNSSEC validation
// )
type ResponseType int

func (t ResponseType) ToExtendedErrorCode() uint16 {
	switch t {
	case ResponseTypeRESOLVED:
		return dns.ExtendedErrorCodeOther
	case ResponseTypeCACHED:
		return dns.ExtendedErrorCodeCachedError
	case ResponseTypeCONDITIONAL:
		return dns.ExtendedErrorCodeForgedAnswer
	case ResponseTypeCUSTOMDNS:
		return dns.ExtendedErrorCodeForgedAnswer
	case ResponseTypeHOSTSFILE:
		return dns.ExtendedErrorCodeForgedAnswer
	case ResponseTypeNOTFQDN:
		return dns.ExtendedErrorCodeBlocked
	case ResponseTypeBLOCKED:
		return dns.ExtendedErrorCodeBlocked
	// RFC 8914: "Blocked" is blocking due to an internal security policy of the
	// operator, "Filtered" is blocking requested by the client. Rebinding
	// protection is operator policy, so it reports as Blocked.
	case ResponseTypeREBIND:
		return dns.ExtendedErrorCodeBlocked
	// EdeResolver sits above the DNSSEC resolver and rewrites the EDE option from
	// the response type, so this must reproduce the code the DNSSEC resolver sets
	// on its SERVFAIL; mapping it to anything else would overwrite Bogus (6).
	case ResponseTypeBOGUS:
		return dns.ExtendedErrorCodeDNSBogus
	case ResponseTypeFILTERED:
		return dns.ExtendedErrorCodeFiltered
	case ResponseTypeSPECIAL:
		return dns.ExtendedErrorCodeFiltered
	case ResponseTypeSYNTHESIZED:
		return dns.ExtendedErrorCodeForgedAnswer
	default:
		return dns.ExtendedErrorCodeOther
	}
}

// Response represents the response of a DNS query
type Response struct {
	Res    *dns.Msg
	Reason string
	// ReasonLabel is a low-cardinality variant of Reason, used as a Prometheus
	// metric label. When empty, metrics fall back to Reason. Blocked responses
	// set this to the matched group names only (without the matched rule), to
	// keep the `reason` label bounded even with large deny lists.
	ReasonLabel string
	RType       ResponseType
}

// RequestProtocol represents the server protocol ENUM(
// TCP // is the TCP protocol
// UDP // is the UDP protocol
// )
type RequestProtocol uint8

// Request represents client's DNS request
type Request struct {
	ClientIP        net.IP
	RequestClientID string
	Protocol        RequestProtocol
	ClientNames     []string
	Req             *dns.Msg
	RequestTS       time.Time
}
