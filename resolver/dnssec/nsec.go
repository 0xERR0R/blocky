package dnssec

// This file contains NSEC-based denial of existence validation per RFC 4035 §5.4.

import (
	"slices"
	"strings"

	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
)

// validateNSECDenialOfExistence validates NSEC-based denial of existence per RFC 4035 §5.4
func (v *Validator) validateNSECDenialOfExistence(response *dns.Msg, question dns.Question) ValidationResult {
	nsecRecords := extractNSECRecords(response.Ns)
	if len(nsecRecords) == 0 {
		return ValidationResultInsecure
	}

	if response.Rcode == dns.RcodeNameError {
		return v.validateNSECNXDOMAIN(nsecRecords, question.Name)
	}

	return v.validateNSECNODATA(nsecRecords, question.Name, question.Qtype)
}

// extractNSECRecords extracts all NSEC records from a slice of RRs
func extractNSECRecords(rrs []dns.RR) []*dns.NSEC {
	return util.ExtractRecordsFromSlice[*dns.NSEC](rrs)
}

// validateNSECNXDOMAIN validates NSEC proof for NXDOMAIN
func (v *Validator) validateNSECNXDOMAIN(nsecRecords []*dns.NSEC, qname string) ValidationResult {
	qname = dns.Fqdn(qname)

	// NXDOMAIN: Need to prove the name doesn't exist
	// Find NSEC that covers the query name
	for _, nsec := range nsecRecords {
		if v.nsecCoversName(nsec, qname) {
			v.logger.Debugf("NSEC covers NXDOMAIN for %s: %s -> %s", qname, nsec.Header().Name, nsec.NextDomain)

			return ValidationResultSecure
		}
	}

	v.logger.Warnf("No NSEC record covers NXDOMAIN for %s", qname)

	return ValidationResultBogus
}

// validateNSECNODATA validates NSEC proof for NODATA
func (v *Validator) validateNSECNODATA(nsecRecords []*dns.NSEC, qname string, qtype uint16) ValidationResult {
	qname = dns.Fqdn(qname)

	// NODATA: Need NSEC at the name proving type doesn't exist
	for _, nsec := range nsecRecords {
		nsecName := dns.Fqdn(nsec.Header().Name)
		if nsecName == qname {
			// NSEC matches the query name - check if it proves type doesn't exist
			if !v.nsecHasType(nsec, qtype) {
				v.logger.Debugf("NSEC proves NODATA for %s type %d", qname, qtype)

				return ValidationResultSecure
			}
			// Type exists according to NSEC - this is bogus
			v.logger.Warnf("NSEC at %s claims type %d exists but no answer returned", qname, qtype)

			return ValidationResultBogus
		}
	}

	v.logger.Warnf("No matching NSEC record found for NODATA proof: %s", qname)

	return ValidationResultBogus
}

// canonicalNameCompare compares two DNS names using RFC 4034 §6.1 canonical ordering.
// Canonical ordering compares labels from the rightmost (root) label first.
// If all shared labels match, the shorter name (fewer labels) comes first.
// Both names are lowercased before comparison.
//
// Returns -1 if a < b, 0 if a == b, +1 if a > b.
func canonicalNameCompare(a, b string) int {
	a = strings.TrimSuffix(strings.ToLower(dns.Fqdn(a)), ".")
	b = strings.TrimSuffix(strings.ToLower(dns.Fqdn(b)), ".")

	labelsA := strings.Split(a, ".")
	labelsB := strings.Split(b, ".")

	// Compare from rightmost label
	idxA := len(labelsA) - 1
	idxB := len(labelsB) - 1

	for idxA >= 0 && idxB >= 0 {
		if cmp := strings.Compare(labelsA[idxA], labelsB[idxB]); cmp != 0 {
			return cmp
		}

		idxA--
		idxB--
	}

	// All compared labels matched; fewer labels sorts first
	return len(labelsA) - len(labelsB)
}

// nsecCoversName checks if an NSEC record covers a given name (for NXDOMAIN proof)
// Per RFC 4034 §4.1: NSEC RR covers names between owner name and next domain name
// Uses RFC 4034 §6.1 canonical DNS name ordering (label-by-label, right to left).
func (v *Validator) nsecCoversName(nsec *dns.NSEC, name string) bool {
	owner := dns.CanonicalName(nsec.Header().Name)
	next := dns.CanonicalName(nsec.NextDomain)
	name = dns.CanonicalName(name)

	// If owner < name < next, then NSEC covers the name
	// Handle wrap-around at end of zone (when next < owner)
	if canonicalNameCompare(next, owner) > 0 {
		// Normal case: owner < next
		return canonicalNameCompare(name, owner) > 0 && canonicalNameCompare(name, next) < 0
	}
	// Wrap-around case: next < owner (covers names from owner to end and start to next)
	return canonicalNameCompare(name, owner) > 0 || canonicalNameCompare(name, next) < 0
}

// nsecHasType checks if an NSEC record claims a given type exists
func (v *Validator) nsecHasType(nsec *dns.NSEC, qtype uint16) bool {
	return slices.Contains(nsec.TypeBitMap, qtype)
}
