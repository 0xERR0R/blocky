package dnssec

// This file contains NSEC3-based denial of existence validation per RFC 5155.

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"slices"
	"strings"

	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
)

// validateNSEC3DenialOfExistence validates NSEC3-based denial of existence per RFC 5155
func (v *Validator) validateNSEC3DenialOfExistence(response *dns.Msg, question dns.Question) ValidationResult {
	qname := dns.Fqdn(question.Name)
	qtype := question.Qtype

	// Extract NSEC3 records
	var nsec3Records []*dns.NSEC3
	for _, rr := range response.Ns {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			nsec3Records = append(nsec3Records, nsec3)
		}
	}

	if len(nsec3Records) == 0 {
		return ValidationResultInsecure
	}

	// Get NSEC3 parameters from first record (all should have same params)
	hashAlg := nsec3Records[0].Hash
	salt := nsec3Records[0].Salt
	iterations := nsec3Records[0].Iterations
	flags := nsec3Records[0].Flags

	// RFC 5155 §6: Check for NSEC3 Opt-Out flag (bit 0)
	// When set, unsigned delegations may exist in the zone
	// Opt-Out handling is implemented in validateNSEC3NXDOMAIN where we check
	// if the name falls in an Opt-Out span and return Insecure instead of Bogus
	const optOutFlag = 0x01
	if flags&optOutFlag != 0 {
		v.logger.Debugf("NSEC3 Opt-Out flag detected for %s - unsigned delegations allowed in Opt-Out spans", qname)
	}

	// RFC 5155 §10.3: Check iteration count limit (DoS protection)
	if iterations > uint16(v.maxNSEC3Iterations) {
		v.logger.Warnf("NSEC3 iteration count %d exceeds maximum %d for %s - treating as Bogus",
			iterations, v.maxNSEC3Iterations, qname)

		return ValidationResultBogus
	}

	// Verify all NSEC3 records use consistent parameters
	for _, nsec3 := range nsec3Records {
		if nsec3.Hash != hashAlg || nsec3.Salt != salt || nsec3.Iterations != iterations {
			v.logger.Warnf("Inconsistent NSEC3 parameters in response for %s", qname)

			return ValidationResultBogus
		}
	}

	// Only SHA-1 (algorithm 1) is currently standardized for NSEC3
	if hashAlg != dns.SHA1 {
		v.logger.Warnf("Unsupported NSEC3 hash algorithm %d for %s", hashAlg, qname)

		return ValidationResultBogus
	}

	// Get zone name from NSEC3 owner name
	// NSEC3 owner name format: <hash>.<zone>
	zoneName := ""
	if len(nsec3Records) > 0 {
		ownerName := nsec3Records[0].Hdr.Name
		labels := dns.SplitDomainName(ownerName)
		if len(labels) > 1 {
			zoneName = dns.Fqdn(strings.Join(labels[1:], "."))
		}
	}

	// RFC 5155 §8: Validate based on response type
	if response.Rcode == dns.RcodeNameError {
		// NXDOMAIN: Need to prove name doesn't exist and no wildcard matches
		return v.validateNSEC3NXDOMAIN(nsec3Records, qname, zoneName, hashAlg, salt, iterations)
	}

	// NODATA: Need to prove name exists but type doesn't
	return v.validateNSEC3NODATA(nsec3Records, qname, qtype, zoneName, hashAlg, salt, iterations)
}

// extractNSEC3Records extracts NSEC3 records from a list of RRs
func extractNSEC3Records(rrs []dns.RR) []*dns.NSEC3 {
	return util.ExtractRecordsFromSlice[*dns.NSEC3](rrs)
}

// computeNSEC3Hash computes the NSEC3 hash per RFC 5155 §5 with caching
// Caching is important because NSEC3 hash computation is expensive (iterative SHA-1)
func (v *Validator) computeNSEC3Hash(name string, hashAlg uint8, salt string, iterations uint16) (string, error) {
	if hashAlg != dns.SHA1 {
		return "", fmt.Errorf("unsupported NSEC3 hash algorithm: %d", hashAlg)
	}

	// Convert name to canonical form for consistent cache keys
	name = dns.Fqdn(strings.ToLower(name))

	// Create cache key: name:algorithm:salt:iterations
	cacheKey := fmt.Sprintf("%s:%d:%s:%d", name, hashAlg, salt, iterations)

	// Check cache first
	if cached, ok := v.nsec3HashCache.Load(cacheKey); ok {
		if hash, ok := cached.(string); ok {
			return hash, nil
		}
	}

	// Compute hash using the miekg/dns library's built-in NSEC3 hash function
	hash := dns.HashName(name, hashAlg, iterations, salt)

	// Store in cache
	v.nsec3HashCache.Store(cacheKey, hash)

	return hash, nil
}

// validateNSEC3NXDOMAIN validates NSEC3 proof for NXDOMAIN per RFC 5155 §8.5
func (v *Validator) validateNSEC3NXDOMAIN(nsec3Records []*dns.NSEC3, qname, zoneName string,
	hashAlg uint8, salt string, iterations uint16,
) ValidationResult {
	// RFC 5155 §8.5: NXDOMAIN requires:
	// 1. Proof that the closest encloser exists
	// 2. Proof that the next closer name does not exist
	// 3. Proof that no wildcard at closest encloser exists

	// Find closest encloser
	closestEncloser := v.findClosestEncloser(qname, zoneName, nsec3Records, hashAlg, salt, iterations)
	if closestEncloser == "" {
		v.logger.Debugf("Could not find closest encloser for %s", qname)

		return ValidationResultBogus
	}

	v.logger.Debugf("Found closest encloser: %s for query %s", closestEncloser, qname)

	// Compute next closer name (one label longer than closest encloser toward qname)
	nextCloser := v.getNextCloser(qname, closestEncloser)
	if nextCloser == "" {
		v.logger.Debugf("Could not compute next closer name")

		return ValidationResultBogus
	}

	// Verify next closer name is covered by an NSEC3 record (proving it doesn't exist)
	nextCloserHash, err := v.computeNSEC3Hash(nextCloser, hashAlg, salt, iterations)
	if err != nil {
		v.logger.Warnf("Failed to compute NSEC3 hash for next closer %s: %v", nextCloser, err)

		return ValidationResultBogus
	}

	if !v.nsec3Covers(nsec3Records, nextCloserHash) {
		v.logger.Debugf("Next closer name %s (hash %s) not covered by any NSEC3", nextCloser, nextCloserHash)

		return ValidationResultBogus
	}

	// RFC 5155 §6: Check for Opt-Out flag
	// If the next closer name is covered by an NSEC3 with Opt-Out flag set,
	// this indicates an unsigned delegation is allowed (Insecure, not Bogus)
	if v.nsec3CoversWithOptOut(nsec3Records, nextCloserHash) {
		v.logger.Debugf("Next closer %s falls in NSEC3 Opt-Out span - unsigned delegation allowed", nextCloser)

		return ValidationResultInsecure
	}

	// Verify wildcard at closest encloser is covered (proving *.closest-encloser doesn't exist)
	wildcardName := "*." + closestEncloser
	wildcardHash, err := v.computeNSEC3Hash(wildcardName, hashAlg, salt, iterations)
	if err != nil {
		v.logger.Warnf("Failed to compute NSEC3 hash for wildcard %s: %v", wildcardName, err)

		return ValidationResultBogus
	}

	if !v.nsec3Covers(nsec3Records, wildcardHash) {
		v.logger.Debugf("Wildcard %s (hash %s) not covered by any NSEC3", wildcardName, wildcardHash)

		return ValidationResultBogus
	}

	v.logger.Debugf("NSEC3 NXDOMAIN proof validated for %s", qname)

	return ValidationResultSecure
}

// validateNSEC3NODATA validates NSEC3 proof for NODATA per RFC 5155 §8.6
func (v *Validator) validateNSEC3NODATA(nsec3Records []*dns.NSEC3, qname string, qtype uint16,
	zoneName string, hashAlg uint8, salt string, iterations uint16,
) ValidationResult {
	// Compute hash of qname
	qnameHash, err := v.computeNSEC3Hash(qname, hashAlg, salt, iterations)
	if err != nil {
		v.logger.Warnf("Failed to compute NSEC3 hash for %s: %v", qname, err)

		return ValidationResultBogus
	}

	// RFC 5155 §8.6: NODATA proof requires NSEC3 record matching qname
	// that doesn't have the requested type in its type bitmap
	if result := v.checkDirectNSEC3Match(nsec3Records, qname, qnameHash, qtype); result != ValidationResultIndeterminate {
		return result
	}

	// No matching NSEC3 record found - might be wildcard NODATA
	return v.checkWildcardNSEC3Match(nsec3Records, qname, qtype, zoneName, hashAlg, salt, iterations, qnameHash)
}

// checkDirectNSEC3Match checks if there's a direct NSEC3 match for NODATA
func (v *Validator) checkDirectNSEC3Match(nsec3Records []*dns.NSEC3, qname, qnameHash string,
	qtype uint16,
) ValidationResult {
	for _, nsec3 := range nsec3Records {
		// Extract just the hash part (first label of owner name)
		ownerName := nsec3.Hdr.Name
		labels := dns.SplitDomainName(ownerName)

		if len(labels) == 0 {
			continue
		}

		if strings.EqualFold(labels[0], qnameHash) {
			// Found matching NSEC3 record - check type bitmap
			if slices.Contains(nsec3.TypeBitMap, qtype) {
				// Type exists in bitmap - this is NOT a valid NODATA proof
				v.logger.Debugf("NSEC3 record for %s has type %d in bitmap", qname, qtype)

				return ValidationResultBogus
			}

			// Matching NSEC3 found and type not in bitmap - valid NODATA
			v.logger.Debugf("NSEC3 NODATA proof validated for %s type %d", qname, qtype)

			return ValidationResultSecure
		}
	}

	return ValidationResultIndeterminate
}

// checkWildcardNSEC3Match checks for wildcard NODATA proof
func (v *Validator) checkWildcardNSEC3Match(nsec3Records []*dns.NSEC3, qname string, qtype uint16,
	zoneName string, hashAlg uint8, salt string, iterations uint16, qnameHash string,
) ValidationResult {
	closestEncloser := v.findClosestEncloser(qname, zoneName, nsec3Records, hashAlg, salt, iterations)
	if closestEncloser == "" {
		v.logger.Debugf("No matching NSEC3 record found for %s (hash %s)", qname, qnameHash)

		// RFC 5155 §6: For DS queries, check if covered by NSEC3 with Opt-Out
		// If yes, this is an unsigned delegation (Insecure), not Bogus
		if qtype == dns.TypeDS && v.nsec3CoversWithOptOut(nsec3Records, qnameHash) {
			v.logger.Debugf("DS query for %s covered by NSEC3 Opt-Out - unsigned delegation", qname)

			return ValidationResultInsecure
		}

		return ValidationResultBogus
	}

	wildcardName := "*." + closestEncloser
	wildcardHash, err := v.computeNSEC3Hash(wildcardName, hashAlg, salt, iterations)
	if err != nil {
		v.logger.Debugf("No matching NSEC3 record found for %s (hash %s)", qname, qnameHash)

		return ValidationResultBogus
	}

	for _, nsec3 := range nsec3Records {
		ownerName := nsec3.Hdr.Name
		labels := dns.SplitDomainName(ownerName)

		if len(labels) > 0 && strings.EqualFold(labels[0], wildcardHash) {
			// Found wildcard NSEC3 - check type bitmap
			if slices.Contains(nsec3.TypeBitMap, qtype) {
				return ValidationResultBogus
			}

			v.logger.Debugf("NSEC3 wildcard NODATA proof validated for %s type %d", qname, qtype)

			return ValidationResultSecure
		}
	}

	v.logger.Debugf("No matching NSEC3 record found for %s (hash %s)", qname, qnameHash)

	// RFC 5155 §6: For DS queries, check if covered by NSEC3 with Opt-Out
	// If yes, this is an unsigned delegation (Insecure), not Bogus
	if qtype == dns.TypeDS && v.nsec3CoversWithOptOut(nsec3Records, qnameHash) {
		v.logger.Debugf("DS query for %s covered by NSEC3 Opt-Out - unsigned delegation", qname)

		return ValidationResultInsecure
	}

	return ValidationResultBogus
}

// findClosestEncloser finds the closest encloser for a name per RFC 5155 §8.3
func (v *Validator) findClosestEncloser(qname, zoneName string, nsec3Records []*dns.NSEC3,
	hashAlg uint8, salt string, iterations uint16,
) string {
	// Start from qname and walk up the tree until we find a matching NSEC3 record
	name := qname
	for {
		nameHash, err := v.computeNSEC3Hash(name, hashAlg, salt, iterations)
		if err != nil {
			return ""
		}

		// Check if any NSEC3 record matches this hash
		for _, nsec3 := range nsec3Records {
			ownerName := nsec3.Hdr.Name
			labels := dns.SplitDomainName(ownerName)
			if len(labels) > 0 && strings.EqualFold(labels[0], nameHash) {
				// Found matching NSEC3 - this is the closest encloser
				return name
			}
		}

		// Don't go above the zone
		// Check this BEFORE moving up to ensure we check the zone apex itself
		if zoneName != "" && name == zoneName {
			// We're at the zone apex and didn't find a match - stop here
			break
		}

		// Move up one label
		labels := dns.SplitDomainName(name)
		if len(labels) <= 1 {
			// Reached zone apex or root
			break
		}

		name = dns.Fqdn(strings.Join(labels[1:], "."))

		// CRITICAL FIX: Always break at root to prevent infinite loop
		if name == "." {
			break
		}

		// Don't go above the zone
		if zoneName != "" && !dns.IsSubDomain(zoneName, name) {
			break
		}
	}

	return ""
}

// getNextCloser returns the next closer name (one label longer than closest encloser)
func (v *Validator) getNextCloser(qname, closestEncloser string) string {
	qnameLabels := dns.SplitDomainName(qname)
	ceLabels := dns.SplitDomainName(closestEncloser)

	if len(qnameLabels) <= len(ceLabels) {
		return ""
	}

	// Next closer is qname with one more label than closest encloser
	nextCloserLabels := qnameLabels[len(qnameLabels)-len(ceLabels)-1:]

	return dns.Fqdn(strings.Join(nextCloserLabels, "."))
}

// compareNSEC3Hashes compares two NSEC3 hash strings as binary values per RFC 5155.
// RFC 5155 specifies that "Hash order" means "the order in which hashed owner names
// are arranged according to their numerical value, treating the leftmost (lowest
// numbered) octet as the most significant octet" (i.e., big-endian comparison).
//
// Returns:
//
//	-1 if hash1 < hash2
//	 0 if hash1 == hash2
//	+1 if hash1 > hash2
//	error if decoding fails
func compareNSEC3Hashes(hash1, hash2 string) (int, error) {
	// Decode base32hex strings to binary
	// NSEC3 uses base32hex encoding (RFC 4648 extended hex alphabet)
	decoder := base32.HexEncoding.WithPadding(base32.NoPadding)

	b1, err := decoder.DecodeString(strings.ToUpper(hash1))
	if err != nil {
		return 0, fmt.Errorf("failed to decode hash1 %s: %w", hash1, err)
	}

	b2, err := decoder.DecodeString(strings.ToUpper(hash2))
	if err != nil {
		return 0, fmt.Errorf("failed to decode hash2 %s: %w", hash2, err)
	}

	// Compare as byte arrays (big-endian)
	return bytes.Compare(b1, b2), nil
}

// nsec3HashInRange checks if a hash falls in the NSEC3 range (ownerHash, nextHash].
// Per RFC 5155, this function handles both normal ordering and wraparound at the end
// of the hash space. Returns true if the hash is covered by the range.
func nsec3HashInRange(hash, ownerHash, nextHash string) bool {
	cmpHashOwner, err := compareNSEC3Hashes(hash, ownerHash)
	if err != nil {
		return false
	}

	cmpHashNext, err := compareNSEC3Hashes(hash, nextHash)
	if err != nil {
		return false
	}

	cmpOwnerNext, err := compareNSEC3Hashes(ownerHash, nextHash)
	if err != nil {
		return false
	}

	if cmpOwnerNext < 0 {
		// Normal case: ownerHash < nextHash
		// Hash must be in range (ownerHash, nextHash]
		return cmpHashOwner > 0 && cmpHashNext <= 0
	}
	// Wraparound case: ownerHash > nextHash (covers end of hash space)
	// Hash is covered if it's either > ownerHash OR <= nextHash
	return cmpHashOwner > 0 || cmpHashNext <= 0
}

// nsec3Covers checks if a hash is covered by any NSEC3 record.
// Per RFC 5155, hashes are compared as binary values (big-endian) not as strings.
func (v *Validator) nsec3Covers(nsec3Records []*dns.NSEC3, hash string) bool {
	for _, nsec3 := range nsec3Records {
		ownerName := nsec3.Hdr.Name
		labels := dns.SplitDomainName(ownerName)
		if len(labels) == 0 {
			continue
		}

		ownerHash := labels[0]
		nextHash := nsec3.NextDomain

		// Check if hash falls in the range (ownerHash, nextHash] using RFC-compliant binary comparison
		if nsec3HashInRange(hash, ownerHash, nextHash) {
			return true
		}
	}

	return false
}

// nsec3CoversWithOptOut checks if a hash is covered by an NSEC3 record with Opt-Out flag set.
// Per RFC 5155 §6: Returns true if the hash falls in an Opt-Out span.
// Hashes are compared as binary values (big-endian) per RFC 5155.
func (v *Validator) nsec3CoversWithOptOut(nsec3Records []*dns.NSEC3, hash string) bool {
	const optOutFlag = 0x01

	for _, nsec3 := range nsec3Records {
		// Skip NSEC3 records without Opt-Out flag
		if nsec3.Flags&optOutFlag == 0 {
			continue
		}

		ownerName := nsec3.Hdr.Name
		labels := dns.SplitDomainName(ownerName)
		if len(labels) == 0 {
			continue
		}

		ownerHash := labels[0]
		nextHash := nsec3.NextDomain

		// Check if hash falls in the range (ownerHash, nextHash] using RFC-compliant binary comparison
		if nsec3HashInRange(hash, ownerHash, nextHash) {
			return true
		}
	}

	return false
}
