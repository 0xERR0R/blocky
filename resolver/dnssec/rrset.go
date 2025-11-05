package dnssec

// This file contains RRset and RRSIG signature validation logic per RFC 4035.

import (
	"context"
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
)

// queryAndMatchDNSKEY queries for DNSKEY records and finds the one matching the key tag
func (v *Validator) queryAndMatchDNSKEY(
	ctx context.Context, signerName string, keyTag uint16,
) (context.Context, *dns.DNSKEY, error) {
	// Query for DNSKEY records
	ctx, keys, err := v.queryDNSKEY(ctx, signerName)
	if err != nil {
		// If we have RRSIG but cannot obtain DNSKEY, this is Bogus (RFC 4035 Section 5.2)
		// The presence of RRSIG indicates DNSSEC is intended, so missing DNSKEY = Bogus
		return ctx, nil, fmt.Errorf("failed to query DNSKEY: %w", err)
	}

	// Find the key that matches the RRSIG's key tag
	matchingKey := findMatchingDNSKEY(keys, keyTag)
	if matchingKey == nil {
		return ctx, nil, fmt.Errorf("no DNSKEY with key tag %d found", keyTag)
	}

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
	case dns.RSASHA1: // Algorithm 5 - deprecated/weak
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

// findMatchingRRSIGsForType finds all RRSIGs that cover the given RRset type
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
func findMatchingDNSKEY(keys []*dns.DNSKEY, keyTag uint16) *dns.DNSKEY {
	for _, key := range keys {
		if key.KeyTag() == keyTag {
			return key
		}
	}

	return nil
}

// isSupportedAlgorithm checks if the DNSSEC algorithm is supported
// Per RFC 4035 §2.2, validators must treat unsupported algorithms as Insecure
func (v *Validator) isSupportedAlgorithm(alg uint8) bool {
	// Supported algorithms as per RFC 8624 (DNSSEC Algorithm Implementation Status)
	// These are the algorithms supported by the miekg/dns library
	switch alg {
	case dns.RSASHA1, // Algorithm 5 (deprecated but still supported)
		dns.RSASHA256,       // Algorithm 8 (recommended)
		dns.RSASHA512,       // Algorithm 10 (recommended)
		dns.ECDSAP256SHA256, // Algorithm 13 (recommended)
		dns.ECDSAP384SHA384, // Algorithm 14 (recommended)
		dns.ED25519,         // Algorithm 15 (recommended)
		dns.ED448:           // Algorithm 16 (recommended, RFC 8080)
		return true
	default:
		return false
	}
}

// verifyRRSIG verifies an RRSIG signature for an RRset
func (v *Validator) verifyRRSIG(
	rrset []dns.RR, rrsig *dns.RRSIG, key *dns.DNSKEY, nsRecords []dns.RR, qname string,
) error {
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
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}
