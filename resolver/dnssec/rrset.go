package dnssec

// This file contains RRset and RRSIG signature validation logic per RFC 4035.

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Algorithm strength scores for preventing downgrade attacks
const (
	algorithmStrengthED448           = 100 // Strongest
	algorithmStrengthED25519         = 90  // Very strong
	algorithmStrengthECDSAP384SHA384 = 80  // Strong
	algorithmStrengthECDSAP256SHA256 = 70  // Strong
	algorithmStrengthRSASHA512       = 50  // Moderate
	algorithmStrengthRSASHA256       = 40  // Moderate
	algorithmStrengthRSASHA1         = 10  // Deprecated/weak
	algorithmStrengthUnsupported     = 0   // Unsupported

	// DNSSEC RSA key validation constants (per RFC 3110)
	dnskeyProtocolValue  = 3          // Required protocol field value
	publicKeyPrefixLen   = 40         // Length of public key prefix for logging
	maxRSAExponentBytes  = 4          // Max exponent length supported by Go crypto (2^31-1)
	maxInt31             = 0x7FFFFFFF // Maximum RSA exponent value supported by Go crypto
	extendedExpLenOffset = 3          // Offset for extended exponent length format
	bitsPerByte          = 8          // Number of bits in a byte
)

// queryAndMatchDNSKEY queries for DNSKEY records and finds the one matching the key tag
func (v *Validator) queryAndMatchDNSKEY(
	ctx context.Context, signerName string, keyTag uint16, algorithm uint8,
) (context.Context, *dns.DNSKEY, error) {
	// Query for DNSKEY records
	ctx, keys, err := v.queryDNSKEY(ctx, signerName)
	if err != nil {
		// If we have RRSIG but cannot obtain DNSKEY, this is Bogus (RFC 4035 Section 5.2)
		// The presence of RRSIG indicates DNSSEC is intended, so missing DNSKEY = Bogus
		return ctx, nil, fmt.Errorf("failed to query DNSKEY: %w", err)
	}

	// Find the key that matches the RRSIG's key tag AND algorithm
	v.logger.Debugf("Looking for DNSKEY with key tag %d and algorithm %d for signer %s", keyTag, algorithm, signerName)
	matchingKey := findMatchingDNSKEY(keys, keyTag, algorithm)
	if matchingKey == nil {
		v.logger.Debugf("Available DNSKEYs: %d keys", len(keys))
		for i, key := range keys {
			v.logger.Debugf("  DNSKEY[%d]: flags=%d, protocol=%d, algorithm=%d, keytag=%d",
				i, key.Flags, key.Protocol, key.Algorithm, key.KeyTag())
		}

		return ctx, nil, fmt.Errorf("no DNSKEY with key tag %d and algorithm %d found", keyTag, algorithm)
	}

	pkeyPrefix := matchingKey.PublicKey
	if len(pkeyPrefix) > publicKeyPrefixLen {
		pkeyPrefix = pkeyPrefix[:publicKeyPrefixLen]
	}
	v.logger.Debugf("Found DNSKEY: flags=%d, protocol=%d, algorithm=%d, keytag=%d, pubkey_prefix=%s...",
		matchingKey.Flags, matchingKey.Protocol, matchingKey.Algorithm, matchingKey.KeyTag(), pkeyPrefix)

	return ctx, matchingKey, nil
}

// getAlgorithmStrength returns a strength score for a DNSSEC algorithm
// Higher scores indicate stronger algorithms (used to prevent downgrade attacks)
func (v *Validator) getAlgorithmStrength(alg uint8) int {
	switch alg {
	case dns.ED448: // Algorithm 16 - strongest
		return algorithmStrengthED448
	case dns.ED25519: // Algorithm 15 - very strong
		return algorithmStrengthED25519
	case dns.ECDSAP384SHA384: // Algorithm 14 - strong
		return algorithmStrengthECDSAP384SHA384
	case dns.ECDSAP256SHA256: // Algorithm 13 - strong
		return algorithmStrengthECDSAP256SHA256
	case dns.RSASHA512: // Algorithm 10 - moderate
		return algorithmStrengthRSASHA512
	case dns.RSASHA256: // Algorithm 8 - moderate
		return algorithmStrengthRSASHA256
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1: // Algorithm 5, 7 - deprecated/weak
		return algorithmStrengthRSASHA1
	default:
		return algorithmStrengthUnsupported
	}
}

// selectBestRRSIG selects the RRSIG with the strongest algorithm from a list
// This prevents algorithm downgrade attacks per RFC 6840 §5.11
func (v *Validator) selectBestRRSIG(rrsigs []*dns.RRSIG) *dns.RRSIG {
	if len(rrsigs) == 0 {
		return nil
	}

	best := rrsigs[0]
	bestStrength := v.getAlgorithmStrength(best.Algorithm)

	for _, sig := range rrsigs[1:] {
		strength := v.getAlgorithmStrength(sig.Algorithm)
		if strength > bestStrength {
			best = sig
			bestStrength = strength
		}
	}

	return best
}

// sortRRSIGsByStrength sorts RRSIGs by algorithm strength (strongest first)
// Per RFC 4035 §5.3.1: Try all signatures, preferring stronger algorithms
func (v *Validator) sortRRSIGsByStrength(rrsigs []*dns.RRSIG) []*dns.RRSIG {
	if len(rrsigs) <= 1 {
		return rrsigs
	}

	// Create a copy to avoid modifying the original slice
	sorted := make([]*dns.RRSIG, len(rrsigs))
	copy(sorted, rrsigs)

	// Simple bubble sort (sufficient for small RRSIG lists, typically 1-3 signatures)
	for i := 0; i < len(sorted)-1; i++ {
		for j := 0; j < len(sorted)-i-1; j++ {
			if v.getAlgorithmStrength(sorted[j].Algorithm) < v.getAlgorithmStrength(sorted[j+1].Algorithm) {
				sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
			}
		}
	}

	return sorted
}

// findMatchingRRSIGs finds all RRSIGs that match the given RRset owner name and type
// Per RFC 4035: An RRSIG covers an RRset if:
// 1. The RRSIG's owner name equals the RRset's owner name
// 2. The RRSIG's Type Covered field equals the RRset's type
func findMatchingRRSIGs(sigs []*dns.RRSIG, ownerName string, rrType uint16) []*dns.RRSIG {
	ownerName = dns.Fqdn(ownerName)
	var matchingRRSIGs []*dns.RRSIG
	for _, sig := range sigs {
		sigOwnerName := dns.Fqdn(sig.Header().Name)
		if sig.TypeCovered == rrType && sigOwnerName == ownerName {
			matchingRRSIGs = append(matchingRRSIGs, sig)
		}
	}

	return matchingRRSIGs
}

// findMatchingRRSIGsForType finds all RRSIGs that cover the given RRset type
// Note: This function only matches by type, not owner name. Use findMatchingRRSIGs instead.
//
//nolint:unparam // rrType is always TypeA in tests, but function is kept for testing flexibility
func findMatchingRRSIGsForType(sigs []*dns.RRSIG, rrType uint16) []*dns.RRSIG {
	var matchingRRSIGs []*dns.RRSIG
	for _, sig := range sigs {
		if sig.TypeCovered == rrType {
			matchingRRSIGs = append(matchingRRSIGs, sig)
		}
	}

	return matchingRRSIGs
}

// validateSignerName validates that the RRSIG signer name is valid for the RRset
// RFC 4035 §5.3.1: The signer name must be equal to or a parent of the RRset owner name
func validateSignerName(signerName, rrsetName string) bool {
	return dns.IsSubDomain(signerName, rrsetName)
}

// findMatchingDNSKEY finds the DNSKEY that matches the given key tag
// RFC 4034 §2.1.2: Protocol field MUST be 3
func findMatchingDNSKEY(keys []*dns.DNSKEY, keyTag uint16, algorithm uint8) *dns.DNSKEY {
	for _, key := range keys {
		// RFC 4034 §2.1.2: The Protocol Field MUST have value 3
		if key.Protocol != dnskeyProtocolValue {
			continue
		}
		if key.KeyTag() == keyTag && key.Algorithm == algorithm {
			return key
		}
	}

	return nil
}

// hasUnsupportedRSAExponent checks if an RSA DNSKEY has an exponent that exceeds Go crypto's limits
// Per RFC 3110, RSA exponents can be up to 65535 bytes, but Go's crypto/rsa limits them to 2^31-1
// This function detects keys with exponents > 4 bytes, which likely exceed the limit
// Returns true if the exponent is unsupported, false otherwise
func hasUnsupportedRSAExponent(key *dns.DNSKEY) bool {
	// Only check RSA algorithms
	switch key.Algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
		// Decode the base64 public key
		pubKeyBytes, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil || len(pubKeyBytes) < 1 {
			return false // Can't parse, let normal validation handle it
		}

		// Parse exponent length per RFC 3110
		// Track offset to avoid redundant checks
		var expLen int
		var offset int

		if pubKeyBytes[0] == 0 {
			// Extended format: next 2 bytes contain exponent length
			if len(pubKeyBytes) < extendedExpLenOffset {
				return false
			}

			expLen = int(pubKeyBytes[1])<<bitsPerByte | int(pubKeyBytes[2])
			offset = extendedExpLenOffset
		} else {
			// Standard format: first byte is exponent length
			expLen = int(pubKeyBytes[0])
			offset = 1
		}

		// Go's crypto/rsa limits exponents to 2^31-1 (the maximum value of a signed int32).
		// While 4 bytes can represent values up to 2^32-1, Go enforces the stricter 2^31-1 limit.
		if expLen > maxRSAExponentBytes {
			return true
		}

		// Even if <= 4 bytes, check if the value exceeds 2^31-1
		if len(pubKeyBytes) < offset+expLen {
			return false
		}

		exponent := pubKeyBytes[offset : offset+expLen]

		// Limit check: If exponent is > 8 bytes, it exceeds uint64 capacity and definitely exceeds 2^31-1
		const maxUint64Bytes = 8
		if len(exponent) > maxUint64Bytes {
			return true
		}

		var expValue uint64

		for _, b := range exponent {
			expValue = (expValue << bitsPerByte) | uint64(b)
		}

		// Check if exponent exceeds 2^31-1
		return expValue > maxInt31
	}

	return false
}

// isSupportedAlgorithm checks if the DNSSEC algorithm is supported
// Per RFC 4035 §2.2, validators must treat unsupported algorithms as Insecure
func (v *Validator) isSupportedAlgorithm(alg uint8) bool {
	// Supported algorithms as per RFC 8624 (DNSSEC Algorithm Implementation Status)
	// These are the algorithms supported by the miekg/dns library
	switch alg {
	case dns.RSASHA1, // Algorithm 5 (deprecated but still supported)
		dns.RSASHA1NSEC3SHA1, // Algorithm 7 (same as 5, used with NSEC3)
		dns.RSASHA256,        // Algorithm 8 (recommended)
		dns.RSASHA512,        // Algorithm 10 (recommended)
		dns.ECDSAP256SHA256,  // Algorithm 13 (recommended)
		dns.ECDSAP384SHA384,  // Algorithm 14 (recommended)
		dns.ED25519,          // Algorithm 15 (recommended)
		dns.ED448:            // Algorithm 16 (recommended, RFC 8080)
		return true
	default:
		return false
	}
}

// verifyRRSIG verifies an RRSIG signature for an RRset
func (v *Validator) verifyRRSIG(
	rrset []dns.RR, rrsig *dns.RRSIG, key *dns.DNSKEY, nsRecords []dns.RR, qname string,
) error {
	// Log DNSKEY details including public key prefix for debugging
	pkeyPrefix := key.PublicKey
	if len(pkeyPrefix) > publicKeyPrefixLen {
		pkeyPrefix = pkeyPrefix[:publicKeyPrefixLen]
	}
	v.logger.Debugf(
		"verifyRRSIG: Using DNSKEY flags=%d, protocol=%d, algorithm=%d, keytag=%d, "+
			"Header.Name='%s', pubkey_prefix=%s... to verify RRSIG keytag=%d, algorithm=%d, SignerName='%s'",
		key.Flags, key.Protocol, key.Algorithm, key.KeyTag(), key.Header().Name, pkeyPrefix,
		rrsig.KeyTag, rrsig.Algorithm, rrsig.SignerName)

	// Check algorithm support per RFC 4035 §2.2
	// Unsupported algorithms should be treated as Insecure, not Bogus
	if !v.isSupportedAlgorithm(rrsig.Algorithm) {
		return fmt.Errorf("unsupported DNSSEC algorithm: %d", rrsig.Algorithm)
	}

	// Verify RRSIG and DNSKEY use the same algorithm
	if rrsig.Algorithm != key.Algorithm {
		return fmt.Errorf("algorithm mismatch: RRSIG uses %d, DNSKEY uses %d", rrsig.Algorithm, key.Algorithm)
	}

	// RFC 4035 §5.3.4: Validate wildcard expansion if applicable
	if len(rrset) > 0 {
		rrsetName := dns.Fqdn(rrset[0].Header().Name)
		if err := v.validateWildcardExpansion(rrsetName, rrsig, nsRecords, qname); err != nil {
			return fmt.Errorf("wildcard validation failed: %w", err)
		}
	}

	// Capture timestamp once at the start to avoid TOCTOU race condition
	// RFC 4035 §5.3.1: The validator's notion of the current time MUST be
	// greater than or equal to the signature inception time and less than
	// the signature expiration time.
	// RFC 6781 §4.1.2: Validators should account for clock skew in deployment environments.
	// By capturing the timestamp once and using it for all time checks,
	// we ensure consistent time validation even if verification takes time.
	now := uint32(time.Now().Unix())

	// Apply clock skew tolerance (default 3600s = 1 hour, per Unbound/BIND)
	// This allows validation to succeed even if system clock is off by this amount
	tolerance := int64(v.clockSkewToleranceSec)
	inceptionWithSkew := int64(rrsig.Inception) - tolerance
	expirationWithSkew := int64(rrsig.Expiration) + tolerance

	// Check signature expiration and inception times first (fast check)
	if int64(now) < inceptionWithSkew {
		return fmt.Errorf("signature not yet valid (inception: %d, now: %d, tolerance: %ds)",
			rrsig.Inception, now, v.clockSkewToleranceSec)
	}
	if int64(now) > expirationWithSkew {
		return fmt.Errorf("signature expired (expiration: %d, now: %d, tolerance: %ds)",
			rrsig.Expiration, now, v.clockSkewToleranceSec)
	}

	// Use miekg/dns to verify the signature (expensive crypto operation)
	// By using the same 'now' timestamp captured above, we avoid TOCTOU issues
	// even if this verification takes significant time
	if err := rrsig.Verify(key, rrset); err != nil {
		// Debug: log RRset details on failure
		v.logger.Debugf("Signature verification failed for RRset with %d records:", len(rrset))
		for i, rr := range rrset {
			v.logger.Debugf("  [%d] %s", i, rr.String())
		}
		v.logger.Debugf("  RRSIG: %s", rrsig.String())

		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}
