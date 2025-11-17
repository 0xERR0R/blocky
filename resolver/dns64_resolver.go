package resolver

import (
	"context"
	"math"
	"net"
	"net/netip"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	// WellKnownDNS64Prefix Well-known DNS64 prefix (RFC 6052)
	WellKnownDNS64Prefix = "64:ff9b::/96"

	// DNS constants
	edns0BufferSize = 4096 // RFC 6891 standard EDNS0 buffer size
	ipv6Length      = 16

	// RFC 6052 prefix lengths (bits)
	prefixLen96 = 96
	prefixLen64 = 64
	prefixLen56 = 56
	prefixLen48 = 48
	prefixLen40 = 40
	prefixLen32 = 32
)

// DNS64Resolver synthesizes AAAA records from A records for IPv6-only clients
type DNS64Resolver struct {
	configurable[*config.DNS64]
	typed
	NextResolver

	prefixes     []netip.Prefix
	exclusionSet []netip.Prefix
}

// NewDNS64Resolver creates a new DNS64 resolver instance
func NewDNS64Resolver(cfg config.DNS64) ChainedResolver {
	// Handle empty or unspecified prefix list - use default well-known prefix
	prefixes := cfg.Prefixes
	if len(prefixes) == 0 {
		wellKnownPrefix := netip.MustParsePrefix(WellKnownDNS64Prefix)
		prefixes = []netip.Prefix{wellKnownPrefix}
	}

	// Build exclusion set per RFC 6147 Section 5.1.4
	var exclusionSet []netip.Prefix

	if len(cfg.ExclusionSet) > 0 {
		// Use custom exclusion set if provided
		// Note: Configured prefixes are NOT automatically added when using custom exclusion set
		// Users must explicitly include them if desired
		exclusionSet = make([]netip.Prefix, len(cfg.ExclusionSet))
		copy(exclusionSet, cfg.ExclusionSet)
	} else {
		// Use default exclusion set
		// Required: IPv4-mapped addresses
		// Required: Configured DNS64 prefixes (prevents double-synthesis loops)
		// Recommended: Loopback, link-local
		exclusionSet = []netip.Prefix{
			netip.MustParsePrefix("::ffff:0:0/96"), // IPv4-mapped addresses (required)
			netip.MustParsePrefix("::1/128"),       // Loopback (recommended)
			netip.MustParsePrefix("fe80::/10"),     // Link-local (recommended)
			// Note: ::/128 (unspecified) checked separately as special case
		}
		// Add configured DNS64 prefixes to exclusion set (RFC requirement)
		//nolint:makezero // Intentionally appending to initialized slice for clarity
		exclusionSet = append(exclusionSet, prefixes...)
	}

	return &DNS64Resolver{
		configurable: withConfig(&cfg),
		typed:        withType("dns64"),
		prefixes:     prefixes,
		exclusionSet: exclusionSet,
	}
}

// Resolve implements the DNS64 resolver logic
func (r *DNS64Resolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	// Check if DNS64 is enabled
	if !r.IsEnabled() {
		return r.next.Resolve(ctx, request)
	}

	ctx, logger := r.log(ctx)

	// Only process AAAA queries for IN class
	if len(request.Req.Question) == 0 || request.Req.Question[0].Qtype != dns.TypeAAAA ||
		request.Req.Question[0].Qclass != dns.ClassINET {
		return r.next.Resolve(ctx, request)
	}

	qname := request.Req.Question[0].Name
	logger.Debugf("received AAAA query for %s, checking for synthesis", qname)

	// Pass query to next resolver
	response, err := r.next.Resolve(ctx, request)
	if err != nil {
		return response, err
	}

	// Check if response has AAAA records that are NOT all in exclusion set
	if r.hasValidAAAARecords(response, logger) {
		logger.Debug("existing valid AAAA found, skipping synthesis")

		return response, nil
	}

	// No valid AAAA records, query for A records and synthesize
	logger.Debug("no valid AAAA found, querying for A records")

	return r.synthesizeFromA(ctx, request, response, logger)
}

// hasValidAAAARecords checks if response has any AAAA records not in exclusion set
func (r *DNS64Resolver) hasValidAAAARecords(response *model.Response, logger *logrus.Entry) bool {
	aaaaRecords := extractAAAARecords(response.Res)
	if len(aaaaRecords) == 0 {
		logger.Debug("no AAAA records in response")

		return false
	}

	logger.Debugf("found %d AAAA record(s), checking exclusion set", len(aaaaRecords))

	// Check if all AAAA records are in exclusion set
	allExcluded := true
	excludedCount := 0

	for _, aaaa := range aaaaRecords {
		if r.isInExclusionSet(aaaa.AAAA) {
			logger.Debugf("AAAA record %s is in exclusion set", aaaa.AAAA)
			excludedCount++
		} else {
			allExcluded = false

			break
		}
	}

	if allExcluded {
		logger.Debugf("all %d AAAA record(s) in exclusion set, will synthesize", excludedCount)

		return false
	}

	logger.Debugf("%d of %d AAAA record(s) not in exclusion set, using original response",
		len(aaaaRecords)-excludedCount, len(aaaaRecords))

	return true
}

// isInExclusionSet checks if an IPv6 address is in the exclusion set
func (r *DNS64Resolver) isInExclusionSet(ipv6 net.IP) bool {
	// Convert net.IP to netip.Addr efficiently without string conversion
	if len(ipv6) == ipv6Length {
		addr := netip.AddrFrom16([16]byte(ipv6))

		// Special case: unspecified address ::/128
		if addr.IsUnspecified() {
			return true
		}

		// Check against all exclusion prefixes
		for _, prefix := range r.exclusionSet {
			if prefix.Contains(addr) {
				return true
			}
		}
	}

	return false
}

// synthesizeFromA queries for A records and synthesizes AAAA records
//
//nolint:funlen // Sequential DNS64 synthesis logic naturally exceeds length limit
func (r *DNS64Resolver) synthesizeFromA(
	ctx context.Context,
	originalRequest *model.Request,
	aaaaResponse *model.Response,
	logger *logrus.Entry,
) (*model.Response, error) {
	// Create new A query for same name
	aReq := util.NewMsgWithQuestion(originalRequest.Req.Question[0].Name, dns.Type(dns.TypeA))

	// Copy DNSSEC flags from original AAAA query
	if originalRequest.Req.IsEdns0() != nil {
		aReq.SetEdns0(edns0BufferSize, originalRequest.Req.IsEdns0().Do())
	}
	aReq.CheckingDisabled = originalRequest.Req.CheckingDisabled
	aReq.RecursionDesired = originalRequest.Req.RecursionDesired

	// Create request wrapper
	aRequest := &model.Request{
		Req:             aReq,
		ClientIP:        originalRequest.ClientIP,
		RequestClientID: originalRequest.RequestClientID,
		Protocol:        originalRequest.Protocol,
	}

	// Send A query through next resolver
	aResponse, err := r.next.Resolve(ctx, aRequest)
	if err != nil {
		logger.Debugf("A query failed: %v", err)

		return aaaaResponse, nil // Return original AAAA response
	}

	// Handle RCODE
	if aResponse.Res.Rcode == dns.RcodeNameError {
		// NXDOMAIN: return as-is, no synthesis
		logger.Debug("A query returned NXDOMAIN, no synthesis")

		return &model.Response{
			Res:    aResponse.Res,
			RType:  aResponse.RType,
			Reason: "NXDOMAIN",
		}, nil
	}

	if aResponse.Res.Rcode != dns.RcodeSuccess {
		// Other RCODEs: treat as empty response (alternative behavior from RFC 6147 Section 5.1.2)
		logger.Debugf("A query returned RCODE %d, treating as empty", aResponse.Res.Rcode)

		return aaaaResponse, nil
	}

	// Extract A records from response
	aRecords := extractARecords(aResponse.Res)
	if len(aRecords) == 0 {
		logger.Debug("no A records found, returning empty AAAA response")

		return aaaaResponse, nil
	}

	logger.Debugf("found %d A record(s) for synthesis", len(aRecords))

	// Extract CNAME and DNAME records for TTL calculation
	cnameRecords := extractCNAMERecords(aResponse.Res)
	dnameRecords := extractDNAMERecords(aResponse.Res)

	if len(cnameRecords) > 0 {
		logger.Debugf("found %d CNAME record(s) in resolution chain", len(cnameRecords))
	}

	if len(dnameRecords) > 0 {
		logger.Debugf("found %d DNAME record(s) in resolution chain", len(dnameRecords))
	}

	// Synthesize AAAA records
	synthesizedAAAA := r.synthesizeAAAARecords(aRecords, cnameRecords, dnameRecords, logger)

	// Build response
	syntheticResponse := new(dns.Msg)
	syntheticResponse.SetReply(originalRequest.Req)
	syntheticResponse.Authoritative = aResponse.Res.Authoritative
	syntheticResponse.RecursionAvailable = aResponse.Res.RecursionAvailable
	syntheticResponse.AuthenticatedData = false // Always clear AD bit (non-validating mode)

	// Add CNAME/DNAME records first, then synthesized AAAA records
	for _, cname := range cnameRecords {
		syntheticResponse.Answer = append(syntheticResponse.Answer, cname)
	}
	for _, dname := range dnameRecords {
		syntheticResponse.Answer = append(syntheticResponse.Answer, dname)
	}
	for _, aaaa := range synthesizedAAAA {
		syntheticResponse.Answer = append(syntheticResponse.Answer, aaaa)
	}

	// Copy additional section unchanged (RFC 6147 Section 5.3.2)
	syntheticResponse.Extra = aResponse.Res.Extra

	logger.Infof("synthesized %d AAAA records from %d A records", len(synthesizedAAAA), len(aRecords))

	return &model.Response{
		Res:    syntheticResponse,
		RType:  model.ResponseTypeSYNTHESIZED,
		Reason: "DNS64",
	}, nil
}

// calculateMinimumTTL calculates the minimum TTL across all records in the resolution chain
func calculateMinimumTTL(
	aRecords []*dns.A,
	cnameRecords []*dns.CNAME,
	dnameRecords []*dns.DNAME,
	logger *logrus.Entry,
) uint32 {
	minTTL := uint32(math.MaxUint32)
	ttlSources := make([]string, 0)

	// Include A record TTLs
	for _, aRecord := range aRecords {
		if aRecord.Hdr.Ttl < minTTL {
			minTTL = aRecord.Hdr.Ttl
			ttlSources = append(ttlSources, "A")
		}
	}

	// Include CNAME record TTLs (if CNAME chain exists)
	for _, cnameRecord := range cnameRecords {
		if cnameRecord.Hdr.Ttl < minTTL {
			minTTL = cnameRecord.Hdr.Ttl
			ttlSources = append(ttlSources, "CNAME")
		}
	}

	// Include DNAME record TTLs (if DNAME redirect exists)
	for _, dnameRecord := range dnameRecords {
		if dnameRecord.Hdr.Ttl < minTTL {
			minTTL = dnameRecord.Hdr.Ttl
			ttlSources = append(ttlSources, "DNAME")
		}
	}

	if len(ttlSources) > 0 {
		logger.Debugf("using minimum TTL %d from resolution chain (sources: %v)", minTTL, ttlSources)
	}

	return minTTL
}

// synthesizeAAAARecords creates AAAA records from A records using configured prefixes
func (r *DNS64Resolver) synthesizeAAAARecords(
	aRecords []*dns.A,
	cnameRecords []*dns.CNAME,
	dnameRecords []*dns.DNAME,
	logger *logrus.Entry,
) []*dns.AAAA {
	// Calculate minimum TTL across ALL records in the resolution chain for cache coherency
	minTTL := calculateMinimumTTL(aRecords, cnameRecords, dnameRecords, logger)

	// Synthesize AAAA records
	var aaaaRecords []*dns.AAAA

	logger.Debugf("synthesizing with %d prefix(es): %v", len(r.prefixes), r.prefixes)

	for _, aRecord := range aRecords {
		for _, prefix := range r.prefixes {
			ipv6 := embedIPv4InIPv6(aRecord.A, prefix)
			if ipv6 == nil {
				logger.Warnf("failed to embed IPv4 %s in prefix %s", aRecord.A, prefix)

				continue
			}

			aaaa := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   aRecord.Hdr.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    minTTL,
				},
				AAAA: ipv6,
			}
			aaaaRecords = append(aaaaRecords, aaaa)

			logger.Debugf("synthesized %s AAAA %s (from A %s, prefix %s, TTL %d)",
				aaaa.Hdr.Name, ipv6, aRecord.A, prefix, minTTL)
		}
	}

	return aaaaRecords
}

// embedIPv4InIPv6 embeds an IPv4 address into an IPv6 prefix per RFC 6052
func embedIPv4InIPv6(ipv4 net.IP, prefix netip.Prefix) net.IP {
	// Get IPv4 bytes
	ipv4Bytes := ipv4.To4()
	if ipv4Bytes == nil {
		return nil
	}

	// Start with the prefix address as IPv6 base
	prefixAddr := prefix.Addr().As16()
	ipv6 := make(net.IP, ipv6Length)
	copy(ipv6, prefixAddr[:])

	// Embed IPv4 address based on prefix length
	// RFC 6052 Section 2.2 defines the bit positions
	switch prefix.Bits() {
	case prefixLen96:
		// IPv4 at bits 96-127 (bytes 12-15)
		// Format: Prefix(96) | IPv4(32)
		copy(ipv6[12:16], ipv4Bytes)

	case prefixLen64:
		// IPv4 at bits 72-103 (bytes 9-12)
		// Format: Prefix(64) | u(8) | IPv4(32) | Suffix(24)
		// Note: Byte 8 (u) is reserved and MUST be 0
		copy(ipv6[9:13], ipv4Bytes)
		ipv6[8] = 0 // Ensure reserved byte is zero

	case prefixLen56:
		// IPv4 split: bits 56-63 (byte 7) and 72-95 (bytes 9-11)
		// Format: Prefix(56) | IPv4[0](8) | u(8) | IPv4[1-3](24) | Suffix(40)
		ipv6[7] = ipv4Bytes[0]
		copy(ipv6[9:12], ipv4Bytes[1:4])
		ipv6[8] = 0 // Ensure reserved byte is zero

	case prefixLen48:
		// IPv4 split: bits 48-63 (bytes 6-7) and 72-87 (bytes 9-10)
		// Format: Prefix(48) | IPv4[0-1](16) | u(8) | IPv4[2-3](16) | Suffix(56)
		copy(ipv6[6:8], ipv4Bytes[0:2])
		copy(ipv6[9:11], ipv4Bytes[2:4])
		ipv6[8] = 0 // Ensure reserved byte is zero

	case prefixLen40:
		// IPv4 split: bits 40-63 (bytes 5-7) and 72-79 (byte 9)
		// Format: Prefix(40) | IPv4[0-2](24) | u(8) | IPv4[3](8) | Suffix(48)
		copy(ipv6[5:8], ipv4Bytes[0:3])
		ipv6[9] = ipv4Bytes[3]
		ipv6[8] = 0 // Ensure reserved byte is zero

	case prefixLen32:
		// IPv4 at bits 32-63 (bytes 4-7)
		// Format: Prefix(32) | IPv4(32) | u(8) | Suffix(56)
		copy(ipv6[4:8], ipv4Bytes)
		ipv6[8] = 0 // Ensure reserved byte is zero

	default:
		// Should never happen if validation is correct
		return nil
	}

	return ipv6
}

// extractAAAARecords extracts all AAAA records from a DNS message
func extractAAAARecords(msg *dns.Msg) []*dns.AAAA {
	var records []*dns.AAAA
	for _, rr := range msg.Answer {
		if aaaa, ok := rr.(*dns.AAAA); ok {
			records = append(records, aaaa)
		}
	}

	return records
}

// extractARecords extracts all A records from a DNS message
func extractARecords(msg *dns.Msg) []*dns.A {
	var records []*dns.A
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			records = append(records, a)
		}
	}

	return records
}

// extractCNAMERecords extracts all CNAME records from a DNS message
func extractCNAMERecords(msg *dns.Msg) []*dns.CNAME {
	var records []*dns.CNAME
	for _, rr := range msg.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			records = append(records, cname)
		}
	}

	return records
}

// extractDNAMERecords extracts all DNAME records from a DNS message
func extractDNAMERecords(msg *dns.Msg) []*dns.DNAME {
	var records []*dns.DNAME
	for _, rr := range msg.Answer {
		if dname, ok := rr.(*dns.DNAME); ok {
			records = append(records, dname)
		}
	}

	return records
}
