package dnssec

// This file contains chain of trust validation logic per RFC 4035.
// It walks the DNSSEC chain from root (trust anchors) to the target domain.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// bogusTTL caps how long a Bogus verdict stays cached, like Unbound's val-bogus-ttl, so a single
// bad answer (an empty or unsigned DNSKEY RRset, say) cannot fail a zone for a whole cache period.
const bogusTTL = time.Minute

// zoneStatus is a cached chain-of-trust verdict for a zone. keys holds the zone's validated
// DNSKEY RRset when result is Secure: signatures are only ever verified with these keys.
type zoneStatus struct {
	result ValidationResult
	keys   []*dns.DNSKEY
}

// validationCacheKey scopes a cached validation result to the upstream view of the originating
// client: the upstream group that answers its DS/DNSKEY sub-queries. Per GHSA-x845-2f78-7v36
// finding 3 the cache must NOT be keyed by bare domain name: a status established for one view
// (split-horizon or upstream group) must not be reused for another. Clients of the same group
// share one view. Requests without a client context share the empty scope.
func validationCacheKey(ctx context.Context, domain string) string {
	cc, _ := clientContextFrom(ctx)

	return cc.view + "\x00" + dns.Fqdn(domain)
}

// getCachedValidation retrieves a cached validation result for the domain within the
// originating client's view (see validationCacheKey).
func (v *Validator) getCachedValidation(ctx context.Context, domain string) (ValidationResult, bool) {
	status := v.cachedZoneStatus(ctx, domain)
	if status == nil {
		return ValidationResultIndeterminate, false
	}

	return status.result, true
}

// cachedZoneStatus returns the unexpired cache entry for domain, or nil.
func (v *Validator) cachedZoneStatus(ctx context.Context, domain string) *zoneStatus {
	status, ttl := v.validationCache.Get(validationCacheKey(ctx, domain))
	// The cache returns expired entries until its cleanup runs; keys must not outlive their TTL.
	if status == nil || ttl <= 0 {
		return nil
	}

	// Record cache hit
	v.cacheHitMetrics.Inc()

	return status
}

// setCachedValidation stores a validation result in the cache, scoped to the originating
// client's view (see validationCacheKey). keys is the zone's validated DNSKEY RRset for a Secure
// result; the entry then expires with the shortest key TTL. A Bogus result expires after bogusTTL.
//
// Indeterminate is never cached. It means "could not determine" - in practice a transient
// sub-query failure (timeout/unreachable upstream) while walking the chain of trust.
// Persisting it would shadow every later RRSIG signed by that zone (the cached Indeterminate
// makes the chain check fail, the signature is skipped, and the answer is declared Bogus ->
// SERVFAIL) for the full cache TTL, even after the upstream recovers - turning one transient
// blip into an hour of failures (issue #2120). Leaving it uncached lets the next query
// re-evaluate the zone and establish its real (durable) status.
func (v *Validator) setCachedValidation(
	ctx context.Context, domain string, result ValidationResult, keys ...*dns.DNSKEY,
) {
	if result == ValidationResultIndeterminate {
		return
	}

	ttl := v.cacheExpiration
	if result == ValidationResultBogus {
		ttl = min(ttl, bogusTTL)
	}

	for _, key := range keys {
		ttl = min(ttl, time.Duration(key.Hdr.Ttl)*time.Second)
	}

	v.validationCache.Put(validationCacheKey(ctx, domain), &zoneStatus{result: result, keys: keys}, ttl)
}

// walkChainOfTrust returns the security status of zone domain and, when it is Secure, the zone's
// validated DNSKEY RRset. The walk starts at the closest trust anchor at or above domain and
// validates each zone below it with the validated keys of the zone above. Every level is cached
// with its keys, so zones share their ancestors' work and a warm chain needs no upstream query.
func (v *Validator) walkChainOfTrust(ctx context.Context, domain string) (ValidationResult, []*dns.DNSKEY) {
	// Normalize the domain name
	domain = dns.Fqdn(domain)

	// Check cache first
	if status := v.cachedZoneStatus(ctx, domain); status != nil {
		v.logger.Debugf("Using cached validation result for %s: %s", domain, status.result.String())

		return status.result, status.keys
	}

	// Split domain into labels
	labels := dns.SplitDomainName(domain)

	// Check chain depth limit to prevent DoS attacks with deeply nested domains
	// RFC does not specify a limit, but we add one for security
	if uint(len(labels)) > v.maxChainDepth {
		v.logger.Warnf("Domain %s exceeds maximum chain depth (%d labels > %d max), rejecting",
			domain, len(labels), v.maxChainDepth)
		v.setCachedValidation(ctx, domain, ValidationResultBogus)

		return ValidationResultBogus, nil
	}

	// zones[i] is the zone made of the last i labels of domain: the root, then down to domain.
	zones := make([]string, len(labels)+1)
	zones[0] = "."

	for i := 1; i < len(zones); i++ {
		zones[i] = dns.Fqdn(strings.Join(labels[len(labels)-i:], "."))
	}

	start := len(zones) - 1
	for start >= 0 && !v.trustAnchors.HasTrustAnchor(zones[start]) {
		start--
	}

	if start < 0 {
		v.logger.Debugf("No trust anchor at or above %s", domain)

		return ValidationResultIndeterminate, nil
	}

	var (
		result ValidationResult
		keys   []*dns.DNSKEY
	)

	for i := start; i < len(zones); i++ {
		if status := v.cachedZoneStatus(ctx, zones[i]); status != nil {
			result, keys = status.result, status.keys
		} else {
			if i == start {
				result, keys = v.verifyDomainAgainstTrustAnchor(ctx, zones[i])
			} else {
				result, keys = v.validateDomainLevel(ctx, zones[i], keys)
			}

			v.setCachedValidation(ctx, zones[i], result, keys...)
		}

		if result != ValidationResultSecure {
			// Zones below an insecure, bogus or unresolved zone share its status.
			return result, nil
		}
	}

	return result, keys
}

// validateDomainLevel validates one zone with the validated DNSKEY RRset of its parent zone:
// the parent must sign the zone's DS RRset (or the proof that it has none), and the zone's
// DNSKEY RRset must match a DS record and be signed by that key (RFC 4035 §5.2).
func (v *Validator) validateDomainLevel(
	ctx context.Context, domain string, parentKeys []*dns.DNSKEY,
) (ValidationResult, []*dns.DNSKEY) {
	v.logger.Debugf("Validating domain level: %s", domain)

	// Query DS records for the child domain from the parent zone
	// Note: The DS query name is the child domain, but the response comes from parent's authority
	dsResponse, err := v.queryRecords(ctx, domain, dns.TypeDS)
	if err != nil {
		v.logger.Warnf("Failed to query DS for %s: %v", domain, err)

		return ValidationResultIndeterminate, nil
	}

	// Extract and validate DS records (may be in answer or authority section)
	dsRecords, result := v.extractAndValidateDSRecords(domain, parentKeys, dsResponse)
	if result != ValidationResultSecure {
		return result, nil
	}

	answer, keys, err := v.queryDNSKEY(ctx, domain)
	if err != nil {
		v.logger.Warnf("Failed to get DNSKEY for %s: %v", domain, err)

		return dnskeyFailure(err), nil
	}

	// Validate at least one DNSKEY against the DS records
	// This validates the KSK (Key Signing Key) which is pointed to by the DS
	validatedKSKs, err := v.findAndValidateKSKs(keys, dsRecords, domain)
	if err != nil {
		v.logger.Warnf("Failed to validate any DNSKEY against DS records for %s: %v", domain, err)

		return ValidationResultBogus, nil
	}

	// CRITICAL: Now verify the DNSKEY RRset itself using the validated KSK
	// Per RFC 4035 §5.2: The DNSKEY RRset MUST be signed by a key in the DNSKEY RRset itself
	// This allows us to trust ALL keys in the set (including ZSKs with different algorithms)
	sig, err := v.verifyDNSKEYRRset(answer, validatedKSKs, domain)
	if err != nil {
		v.logger.Warnf("Failed to verify DNSKEY RRset for %s: %v", domain, err)

		return ValidationResultBogus, nil
	}

	v.logger.Debugf("Successfully validated DNSKEY for %s", domain)

	return ValidationResultSecure, keysUntilSignatureExpiry(keys, sig)
}

// keysUntilSignatureExpiry returns copies of keys whose TTLs do not exceed the TTL, the original
// TTL or the remaining lifetime of sig, the RRSIG that validated their RRset (RFC 4035 §5.3.3).
func keysUntilSignatureExpiry(keys []*dns.DNSKEY, sig *dns.RRSIG) []*dns.DNSKEY {
	remaining := max(int64(sig.Expiration)-time.Now().Unix(), 0)
	ttl := min(sig.Hdr.Ttl, sig.OrigTtl, uint32(remaining)) //nolint:gosec // remaining is below the uint32 expiration

	capped := make([]*dns.DNSKEY, 0, len(keys))

	for _, key := range keys {
		keyCopy := *key
		keyCopy.Hdr.Ttl = min(keyCopy.Hdr.Ttl, ttl)
		capped = append(capped, &keyCopy)
	}

	return capped
}

// dnskeyFailure maps a queryDNSKEY error to a result: keys that could not be retrieved leave the
// zone Indeterminate (issue #2120), an answer without keys is Bogus.
func dnskeyFailure(err error) ValidationResult {
	if errors.Is(err, errDNSKEYUnavailable) {
		return ValidationResultIndeterminate
	}

	return ValidationResultBogus
}

// validateDNSKEY validates a DNSKEY against a DS record from parent zone
func (v *Validator) validateDNSKEY(dnskey *dns.DNSKEY, parentDS *dns.DS) error {
	// RFC 4035 §5.2: DS Algorithm field must match DNSKEY Algorithm field
	if dnskey.Algorithm != parentDS.Algorithm {
		return fmt.Errorf("algorithm mismatch: DNSKEY uses %d, DS expects %d", dnskey.Algorithm, parentDS.Algorithm)
	}

	// RFC 4035 §5.2: DS Key Tag field must match DNSKEY Key Tag field
	kskTag := dnskey.KeyTag()
	if kskTag != parentDS.KeyTag {
		return fmt.Errorf("keytag mismatch: DNSKEY uses %d, DS expects %d", kskTag, parentDS.KeyTag)
	}

	// Calculate the DS digest from the DNSKEY
	calculatedDS := dnskey.ToDS(parentDS.DigestType)
	if calculatedDS == nil {
		return fmt.Errorf("unsupported DS digest type: %d", parentDS.DigestType)
	}

	// Compare the digests
	if calculatedDS.Digest != parentDS.Digest {
		return fmt.Errorf("DS digest mismatch: expected %s, got %s", parentDS.Digest, calculatedDS.Digest)
	}

	return nil
}

// validateAnyDNSKEY validates at least one DNSKEY against DS records
// This is a convenience wrapper around findAndValidateKSKs for callers that only need a bool result
//
//nolint:unparam // domain parameter used for logging, test usage pattern is acceptable
func (v *Validator) validateAnyDNSKEY(keys []*dns.DNSKEY, dsRecords []*dns.DS, domain string) bool {
	ksks, err := v.findAndValidateKSKs(keys, dsRecords, domain)

	return err == nil && len(ksks) > 0
}

// findAndValidateKSKs validates DNSKEYs against DS records and returns all validated KSKs
// This function is similar to validateAnyDNSKEY but returns the validated keys instead of bool
func (v *Validator) findAndValidateKSKs(keys []*dns.DNSKEY, dsRecords []*dns.DS, domain string) ([]*dns.DNSKEY, error) {
	const REVOKE = 0x0080                  // RFC 5011 §7: REVOKE flag (bit 8)
	const maxDNSKEYValidationAttempts = 16 // Caps digest validation attempts (KeyTrap, CVE-2023-50387).

	validationAttempts := 0
	var validKSKs []*dns.DNSKEY

outer:
	for _, key := range keys {
		// Per RFC 4034 §2.1.1: Only validate keys with the ZONE flag (bit 7) set
		if key.Flags&dns.ZONE == 0 {
			continue
		}

		// RFC 5011 §7: DNSKEYs with REVOKE flag MUST NOT be used
		if key.Flags&REVOKE != 0 {
			continue
		}

		kskTag := key.KeyTag()
		for _, ds := range dsRecords {
			// RFC 4035 §5.2 requires both Key Tag and Algorithm to match
			// This check is cheap so it does not count against our validation budget
			if kskTag != ds.KeyTag || key.Algorithm != ds.Algorithm {
				continue
			}

			// Limit the number of key validations to prevent DoS
			if validationAttempts == maxDNSKEYValidationAttempts {
				if len(validKSKs) == 0 {
					return nil, fmt.Errorf("exceeded KSK validation budget (%d attempts)", validationAttempts)
				}

				v.logger.Warnf("Exceeded KSK validation budget for domain %s, stopping with %d validated KSKs",
					domain, len(validKSKs))

				break outer
			}
			validationAttempts++

			if err := v.validateDNSKEY(key, ds); err == nil {
				v.logger.Debugf("Validated KSK for %s: flags=%d, algorithm=%d, keytag=%d",
					domain, key.Flags, key.Algorithm, kskTag)

				validKSKs = append(validKSKs, key)

				break
			}
		}
	}

	if len(validKSKs) == 0 {
		return nil, errors.New("no DNSKEY matches the parent DS RRset")
	}

	return validKSKs, nil
}

// verifyDNSKEYRRset verifies the DNSKEY RRset using validated KSKs and returns the RRSIG that verified it
// Per RFC 4035 §5.2: The DNSKEY RRset MUST be self-signed by a key in the set
// This validates all keys in the RRset, including ZSKs with different algorithms
func (v *Validator) verifyDNSKEYRRset(
	answer []dns.RR, validatedKSKs []*dns.DNSKEY, domain string,
) (*dns.RRSIG, error) {
	// Extract DNSKEY records and RRSIGs from the answer section
	var dnskeyRecords []dns.RR
	var rrsigs []*dns.RRSIG

	for _, rr := range answer {
		switch r := rr.(type) {
		case *dns.DNSKEY:
			dnskeyRecords = append(dnskeyRecords, r)
		case *dns.RRSIG:
			if r.TypeCovered == dns.TypeDNSKEY {
				rrsigs = append(rrsigs, r)
			}
		}
	}

	if len(validatedKSKs) == 0 {
		return nil, errors.New("no validated KSKs provided")
	}

	if len(dnskeyRecords) == 0 {
		return nil, errors.New("no DNSKEY records found in answer")
	}

	if len(rrsigs) == 0 {
		return nil, errors.New("no RRSIG records found for DNSKEY RRset")
	}

	sig, err := v.verifyRRSIGMatch(validatedKSKs, dnskeyRecords, rrsigs, domain)
	if err != nil {
		return nil, fmt.Errorf("DNSKEY RRset signature verification failed: %w", err)
	}

	return sig, nil
}

// verifyRRSIGMatch returns an RRSIG made by one of the validated KSKs that verifies the RRset
func (v *Validator) verifyRRSIGMatch(
	validatedKSKs []*dns.DNSKEY, dnskeyRecords []dns.RR, rrsigs []*dns.RRSIG, domain string,
) (*dns.RRSIG, error) {
	const maxRRSIGVerificationAttempts = 8 // Caps signature verification attempts (KeyTrap, CVE-2023-50387)

	// Per RFC 4035 §2.2: For DNSKEY RRsets, the signer must equal the owner
	domainFQDN := dns.CanonicalName(domain)
	var sigErrors []error
	verifyAttempts := 0

	// Iterate through validated KSKs and check against available RRSIGs
	for _, ksk := range validatedKSKs {
		kskTag := ksk.KeyTag()

		for _, sig := range rrsigs {
			// Match by KeyTag, Algorithm, AND SignerName for security
			if sig.KeyTag != kskTag ||
				sig.Algorithm != ksk.Algorithm ||
				dns.CanonicalName(sig.SignerName) != domainFQDN {
				continue
			}

			// Attempt to verify the DNSKEY RRset with this KSK and signature
			err := v.verifyRRSIG(dnskeyRecords, sig, ksk, nil, domain)
			if err == nil {
				v.logger.Debugf("Successfully verified DNSKEY RRset for %s with KSK keytag=%d",
					domain, kskTag)

				return sig, nil
			}

			sigErrors = append(sigErrors, fmt.Errorf("keytag=%d: %w", kskTag, err))

			// Give up verification after some number of attempts to prevent DoS
			// Only failed cryptographic verifications count against the budget
			if !errors.Is(err, errRRSIGVerificationFailed) {
				continue
			}
			verifyAttempts++
			if verifyAttempts >= maxRRSIGVerificationAttempts {
				return nil, fmt.Errorf("giving up after %d verification attempts: %w",
					verifyAttempts, errors.Join(sigErrors...))
			}
		}
	}

	if sigErrors == nil {
		var kskDetails []string
		for _, ksk := range validatedKSKs {
			kskDetails = append(kskDetails, fmt.Sprintf("(keytag=%d, algorithm=%d)", ksk.KeyTag(), ksk.Algorithm))
		}

		return nil, fmt.Errorf("no RRSIG found for validated KSKs %s", strings.Join(kskDetails, "; "))
	}

	return nil, errors.Join(sigErrors...)
}

// verifyDomainAgainstTrustAnchor validates the DNSKEY RRset of a zone with a configured trust
// anchor. The RRset must contain an anchored key, and an anchored key must sign it unless the
// RRset holds anchored keys only.
func (v *Validator) verifyDomainAgainstTrustAnchor(
	ctx context.Context, domain string,
) (ValidationResult, []*dns.DNSKEY) {
	const REVOKE = 0x0080 // RFC 5011 §7: REVOKE flag (bit 8)

	// Get trust anchors for this domain
	trustAnchors := v.trustAnchors.GetTrustAnchors(domain)
	if len(trustAnchors) == 0 {
		v.logger.Warnf("No trust anchors configured for %s", domain)

		return ValidationResultIndeterminate, nil
	}

	// Query DNSKEY for the domain
	answer, keys, err := v.queryDNSKEY(ctx, domain)
	if err != nil {
		v.logger.Warnf("Failed to get DNSKEY for %s: %v", domain, err)

		return dnskeyFailure(err), nil
	}

	// Trust anchors are DNSKEY records - validate by matching key content
	var anchored []*dns.DNSKEY

	for _, key := range keys {
		// Only consider keys with the Zone Key flag set; RFC 5011 §7: skip revoked keys
		if key.Flags&dns.ZONE == 0 || key.Flags&REVOKE != 0 {
			continue
		}

		if slices.ContainsFunc(trustAnchors, func(anchor *TrustAnchor) bool {
			return key.PublicKey == anchor.Key.PublicKey &&
				key.Algorithm == anchor.Key.Algorithm &&
				key.Flags == anchor.Key.Flags
		}) {
			anchored = append(anchored, key)
		}
	}

	if len(anchored) == 0 {
		v.logger.Warnf("Failed to validate DNSKEY for %s against any trust anchor", domain)

		return ValidationResultBogus, nil
	}

	sig, err := v.verifyDNSKEYRRset(answer, anchored, domain)
	if err != nil {
		// Without the anchor's signature nothing vouches for the other keys of the RRset, and the
		// zone signs with them (the root's ZSK signs every TLD's DS RRset).
		if len(anchored) < len(keys) {
			v.logger.Warnf("DNSKEY RRset for %s is not signed by its trust anchor: %v", domain, err)

			return ValidationResultBogus, nil
		}

		v.logger.Debugf("DNSKEY RRset for %s holds only anchored keys and no anchor signature", domain)

		return ValidationResultSecure, keys
	}

	v.logger.Debugf("Successfully validated DNSKEY for %s against trust anchor", domain)

	return ValidationResultSecure, keysUntilSignatureExpiry(keys, sig)
}

// getParentDomain returns the parent domain of the given domain
// Returns empty string if the domain is root or has no parent
func (v *Validator) getParentDomain(domain string) string {
	domain = dns.Fqdn(domain)

	// Root has no parent
	if domain == "." {
		return ""
	}

	// Split domain into labels
	labels := dns.SplitDomainName(domain)
	if len(labels) <= 1 {
		// TLD, parent is root
		return "."
	}

	// Build parent domain from all labels except the first
	parentLabels := labels[1:]
	parent := dns.Fqdn(strings.Join(parentLabels, "."))

	return parent
}

// validateDSRecordSignature validates a DS record RRSIG with the validated DNSKEY RRset of the
// parent zone
func (v *Validator) validateDSRecordSignature(
	ctx context.Context, domain, parentDomain string, dsRRset []dns.RR, dsRRSIG *dns.RRSIG,
) ValidationResult {
	parentResult, parentKeys := v.walkChainOfTrust(ctx, parentDomain)
	if parentResult != ValidationResultSecure {
		v.logger.Warnf("Parent zone %s of %s is %s, cannot validate its DS RRset",
			parentDomain, domain, parentResult.String())

		return parentResult
	}

	if err := v.verifyWithZoneKeys(dsRRset, []*dns.RRSIG{dsRRSIG}, parentKeys); err != nil {
		v.logger.Warnf("DS RRSIG verification failed for %s: %v", domain, err)

		return ValidationResultBogus
	}

	v.logger.Debugf("Successfully validated DS records for %s using parent zone's DNSKEY", domain)

	return ValidationResultSecure
}

// extractAndValidateDSRecords extracts DS records from a response and validates their RRSIG
// with the validated keys of the parent zone
// Per RFC 4035 §5.2: "The DS RRset MUST be signed by the parent zone's DNSKEY"
func (v *Validator) extractAndValidateDSRecords(
	domain string, parentKeys []*dns.DNSKEY, dsResponse *dns.Msg,
) ([]*dns.DS, ValidationResult) {
	// Extract DS records (may be in answer or authority section)
	dsRecords, err := extractTypedRecords[*dns.DS](dsResponse.Answer, dsResponse.Ns)
	if err != nil {
		// No DS records found - check for authenticated denial of existence
		return v.handleDSAbsence(domain, parentKeys, dsResponse)
	}

	sigs := findMatchingRRSIGsForType(extractRRSIGs(slices.Concat(dsResponse.Answer, dsResponse.Ns)), dns.TypeDS)
	if err := v.verifyWithZoneKeys(convertDSToRRset(dsRecords), sigs, parentKeys); err != nil {
		v.logger.Warnf("DS RRset for %s is not signed by its parent zone: %v", domain, err)

		return nil, ValidationResultBogus
	}

	return dsRecords, ValidationResultSecure
}

// handleDSAbsence handles the case where no DS records are found
// Per RFC 4035 §5.2: DS absent can mean:
// 1. Unsigned delegation (Insecure) - proven by NSEC/NSEC3 signed by the parent zone
// 2. Missing proof (Indeterminate) - no DS and no NSEC/NSEC3
func (v *Validator) handleDSAbsence(
	domain string, parentKeys []*dns.DNSKEY, dsResponse *dns.Msg,
) ([]*dns.DS, ValidationResult) {
	// Check for NSEC/NSEC3 records proving DS doesn't exist
	hasNSEC := len(extractNSECRecords(dsResponse.Ns)) > 0
	hasNSEC3 := len(extractNSEC3Records(dsResponse.Ns)) > 0

	if !hasNSEC && !hasNSEC3 {
		// No DS and no proof of absence - cannot determine if delegation is secure
		v.logger.Warnf("No DS records for %s and no NSEC/NSEC3 proof - indeterminate", domain)

		return nil, ValidationResultIndeterminate
	}

	// A denial proves nothing unless the parent zone signed it
	if err := v.verifyDenialSignatures(dsResponse.Ns, parentKeys); err != nil {
		v.logger.Warnf("NSEC/NSEC3 proof of DS absence for %s is not signed by its parent zone: %v", domain, err)

		return nil, ValidationResultBogus
	}

	// Validate NSEC/NSEC3 proof that DS doesn't exist
	validationResult := v.validateDSAbsenceProof(domain, dsResponse, hasNSEC)

	if validationResult == ValidationResultSecure || validationResult == ValidationResultInsecure {
		// Authenticated denial of existence OR NSEC3 opt-out - this is an unsigned delegation
		v.logger.Debugf("Validated NSEC/NSEC3 proof that DS doesn't exist for %s - insecure delegation", domain)

		return nil, ValidationResultInsecure
	}

	// NSEC/NSEC3 validation failed - could be an attack
	v.logger.Warnf("NSEC/NSEC3 records present but failed to prove DS absence for %s - treating as Bogus", domain)

	return nil, ValidationResultBogus
}

// verifyDenialSignatures checks that every NSEC and NSEC3 RRset in rrs is signed by one of keys
func (v *Validator) verifyDenialSignatures(rrs []dns.RR, keys []*dns.DNSKEY) error {
	sigs := extractRRSIGs(rrs)

	for key, rrset := range groupRRsetsByNameAndType(rrs) {
		if key.rrType != dns.TypeNSEC && key.rrType != dns.TypeNSEC3 {
			continue
		}

		if err := v.verifyWithZoneKeys(rrset, findMatchingRRSIGs(sigs, key.name, key.rrType), keys); err != nil {
			return fmt.Errorf("%s %s: %w", key.name, dns.TypeToString[key.rrType], err)
		}
	}

	return nil
}

// validateDSAbsenceProof validates NSEC or NSEC3 proof that DS doesn't exist
func (v *Validator) validateDSAbsenceProof(domain string, dsResponse *dns.Msg, hasNSEC bool) ValidationResult {
	// Create a synthetic question for DS query validation
	dsQuestion := dns.Question{
		Name:   domain,
		Qtype:  dns.TypeDS,
		Qclass: dns.ClassINET,
	}

	if hasNSEC {
		// Validate NSEC proof of DS absence (NODATA proof)
		nsecRecords := extractNSECRecords(dsResponse.Ns)

		// A DS-absence NODATA proof only proves an INSECURE DELEGATION if the matching NSEC
		// asserts a delegation: NS bit set, SOA and DS bits clear (RFC 6840 §4.4, RFC 4035
		// §5.2). An NSEC for an ordinary in-zone name (NS bit clear) or a zone apex (SOA bit
		// set) does not - the name lives inside the signed zone, so a missing-signature answer
		// for it is bogus, not insecure (GHSA-x845-2f78-7v36 finding 4).
		if !v.nsecProvesInsecureDelegation(nsecRecords, domain) {
			v.logger.Warnf("NSEC DS-absence proof for %s does not assert an insecure delegation "+
				"(NS bit clear or SOA/DS bit set) - not an unsigned delegation", domain)

			return ValidationResultBogus
		}

		return v.validateNSECNODATA(nsecRecords, domain, dns.TypeDS)
	}

	// Validate NSEC3 proof of DS absence (NODATA proof)
	result := v.validateNSEC3DenialOfExistence(dsResponse, dsQuestion)

	// A name that does not exist is no delegation and has no keys to sign with. Only an Opt-Out
	// span (Insecure) may hold an unsigned delegation that the denial does not show (RFC 5155 §6).
	if dsResponse.Rcode == dns.RcodeNameError && result == ValidationResultSecure {
		v.logger.Warnf("NSEC3 proof shows that %s does not exist - not an unsigned delegation", domain)

		return ValidationResultBogus
	}

	return result
}

// nsecProvesInsecureDelegation reports whether an NSEC RR matching domain asserts an insecure
// delegation per RFC 6840 §4.4 (the NS-set/SOA-clear/DS-clear rule shared with NSEC3 via
// assertsInsecureDelegation). This distinguishes a genuine unsigned delegation from an ordinary
// name inside a signed zone or the apex of a signed zone, neither of which may be treated as an
// insecure delegation when proving DS absence.
func (v *Validator) nsecProvesInsecureDelegation(nsecRecords []*dns.NSEC, domain string) bool {
	domain = dns.Fqdn(domain)
	for _, nsec := range nsecRecords {
		if dns.Fqdn(nsec.Header().Name) != domain {
			continue
		}

		return assertsInsecureDelegation(nsec.TypeBitMap)
	}

	return false
}

// findDSRRSIG finds the RRSIG for DS records in the response
func (v *Validator) findDSRRSIG(dsResponse *dns.Msg, domain string) *dns.RRSIG {
	dsSignatures := extractRRSIGs(append(dsResponse.Answer, dsResponse.Ns...))

	for _, sig := range dsSignatures {
		if sig.TypeCovered == dns.TypeDS {
			return sig
		}
	}

	v.logger.Warnf("No RRSIG found for DS records of %s", domain)

	return nil
}

// convertDSToRRset converts DS records to a generic RR slice for signature verification
func convertDSToRRset(dsRecords []*dns.DS) []dns.RR {
	dsRRset := make([]dns.RR, 0, len(dsRecords))
	for _, ds := range dsRecords {
		dsRRset = append(dsRRset, ds)
	}

	return dsRRset
}

// extractTypedRecords extracts records of a specific type from RR slices using Go generics
func extractTypedRecords[T dns.RR](rrs ...[]dns.RR) ([]T, error) {
	var results []T
	for _, rrList := range rrs {
		for _, rr := range rrList {
			if typed, ok := rr.(T); ok {
				results = append(results, typed)
			}
		}
	}
	if len(results) == 0 {
		return nil, errors.New("no records of requested type found")
	}

	return results, nil
}
