package dnssec

// This file contains chain of trust validation logic per RFC 4035.
// It walks the DNSSEC chain from root (trust anchors) to the target domain.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/0xERR0R/blocky/log"
	"github.com/miekg/dns"
)

// validationCacheKey scopes a cached validation result to the originating client's view
// (the same identity that selects the upstream group for DS/DNSKEY sub-queries). Per
// GHSA-x845-2f78-7v36 finding 3 the cache must NOT be keyed by bare domain name: a status
// established for one view (conditional-forwarding branch, split-horizon, or upstream group)
// must not be reused for another. Requests without a client context share the empty scope.
func validationCacheKey(ctx context.Context, domain string) string {
	domain = dns.Fqdn(domain)

	cc, ok := clientContextFrom(ctx)
	if !ok {
		return "\x00" + domain
	}

	var ip string
	if cc.ip != nil {
		ip = cc.ip.String()
	}

	return cc.clientID + "\x00" + strings.Join(cc.names, ",") + "\x00" + ip + "\x00" + domain
}

// getCachedValidation retrieves a cached validation result for the domain within the
// originating client's view (see validationCacheKey).
func (v *Validator) getCachedValidation(ctx context.Context, domain string) (ValidationResult, bool) {
	result, _ := v.validationCache.Get(validationCacheKey(ctx, domain))
	if result == nil {
		return ValidationResultIndeterminate, false
	}

	// Record cache hit
	v.cacheHitMetrics.Inc()

	return *result, true
}

// setCachedValidation stores a validation result in the cache, scoped to the originating
// client's view (see validationCacheKey).
//
// Indeterminate is never cached. It means "could not determine" - in practice a transient
// sub-query failure (timeout/unreachable upstream) while walking the chain of trust.
// Persisting it would shadow every later RRSIG signed by that zone (the cached Indeterminate
// makes the chain check fail, the signature is skipped, and the answer is declared Bogus ->
// SERVFAIL) for the full cache TTL, even after the upstream recovers - turning one transient
// blip into an hour of failures (issue #2120). Leaving it uncached lets the next query
// re-evaluate the zone and establish its real (durable) status.
func (v *Validator) setCachedValidation(ctx context.Context, domain string, result ValidationResult) {
	if result == ValidationResultIndeterminate {
		return
	}

	v.validationCache.Put(validationCacheKey(ctx, domain), &result, v.cacheExpiration)
}

// walkChainOfTrust walks the chain of trust from root to target domain
func (v *Validator) walkChainOfTrust(ctx context.Context, domain string) ValidationResult {
	// Normalize the domain name
	domain = dns.Fqdn(domain)

	// Check cache first
	if cached, found := v.getCachedValidation(ctx, domain); found {
		v.logger.DebugContext(ctx, "using cached validation result",
			slog.String("domain", domain), slog.String("result", cached.String()))

		return cached
	}

	// Split domain into labels
	labels := dns.SplitDomainName(domain)

	// Check chain depth limit to prevent DoS attacks with deeply nested domains
	// RFC does not specify a limit, but we add one for security
	if uint(len(labels)) > v.maxChainDepth {
		v.logger.WarnContext(ctx, "domain exceeds maximum chain depth",
			slog.String("domain", domain), slog.Int("labels", len(labels)), slog.Int("max_depth", int(v.maxChainDepth)))
		result := ValidationResultBogus
		v.setCachedValidation(ctx, domain, result)

		return result
	}

	// If this is the root, verify against trust anchors
	if domain == "." {
		result := v.verifyAgainstTrustAnchors(ctx)
		v.setCachedValidation(ctx, domain, result)

		return result
	}

	// Walk from root down to target domain
	currentDomain := "."
	for i, label := range slices.Backward(labels) {
		// Build the domain for this level
		if i == len(labels)-1 {
			currentDomain = label + "."
		} else {
			currentDomain = label + "." + currentDomain
		}

		// Check if this domain has a configured trust anchor
		if v.trustAnchors.HasTrustAnchor(currentDomain) {
			v.logger.DebugContext(ctx, "domain has a configured trust anchor, verifying DNSKEY",
				slog.String("domain", currentDomain))
			// Trust anchor found - verify that actual DNSKEY from DNS matches the trust anchor
			result := v.verifyDomainAgainstTrustAnchor(ctx, currentDomain)
			if result != ValidationResultSecure {
				v.setCachedValidation(ctx, domain, result)

				return result
			}
			// Trust anchor verified, continue to validate child zones
			continue
		}

		// Validate this level of the chain
		result := v.validateDomainLevel(ctx, currentDomain)
		if result != ValidationResultSecure {
			v.setCachedValidation(ctx, domain, result)

			return result
		}
	}

	// Cache successful validation
	v.setCachedValidation(ctx, domain, ValidationResultSecure)

	return ValidationResultSecure
}

// validateDomainLevel validates a single level in the DNSSEC chain
func (v *Validator) validateDomainLevel(ctx context.Context, domain string) ValidationResult {
	v.logger.DebugContext(ctx, "validating domain level", slog.String("domain", domain))

	// Query DS records from parent zone
	// Per RFC 4034 §5: DS records are published in the PARENT zone, not the child
	parentDomain := v.getParentDomain(domain)
	if parentDomain == "" {
		// Root domain has no parent
		v.logger.DebugContext(ctx, "domain has no parent, cannot validate via DS", slog.String("domain", domain))

		return ValidationResultInsecure
	}

	// CRITICAL FIX: Per RFC 4035 §5.2, we must validate the parent zone's DNSKEY
	// BEFORE trusting the DS records from that parent zone
	// First, ensure the parent zone itself is validated (recursive chain validation)
	parentResult := v.walkChainOfTrust(ctx, parentDomain)
	if parentResult != ValidationResultSecure {
		v.logger.WarnContext(ctx, "parent zone validation failed",
			slog.String("parent", parentDomain), slog.String("result", parentResult.String()))

		return parentResult
	}

	// Query DS records for the child domain from the parent zone
	// Note: The DS query name is the child domain, but the response comes from parent's authority
	ctx, dsResponse, err := v.queryRecords(ctx, domain, dns.TypeDS)
	if err != nil {
		v.logger.WarnContext(ctx, "failed to query DS records", slog.String("domain", domain), log.AttrError(err))

		return ValidationResultIndeterminate
	}

	// Extract and validate DS records (may be in answer or authority section)
	dsRecords, result := v.extractAndValidateDSRecords(ctx, domain, parentDomain, dsResponse)
	if result != ValidationResultSecure {
		return result
	}

	// Query DNSKEY records for current domain (need full response for RRSIGs)
	_, dnskeyResponse, err := v.queryRecords(ctx, domain, dns.TypeDNSKEY)
	if err != nil {
		v.logger.WarnContext(ctx, "failed to query DNSKEY records", slog.String("domain", domain), log.AttrError(err))

		return ValidationResultIndeterminate
	}

	// Extract DNSKEY records from response
	keys, err := extractTypedRecords[*dns.DNSKEY](dnskeyResponse.Answer)
	if err != nil {
		v.logger.WarnContext(ctx, "failed to extract DNSKEY records", slog.String("domain", domain), log.AttrError(err))

		return ValidationResultIndeterminate
	}

	// Validate at least one DNSKEY against the DS records
	// This validates the KSK (Key Signing Key) which is pointed to by the DS
	validatedKSK := v.findAndValidateKSK(keys, dsRecords, domain)
	if validatedKSK == nil {
		v.logger.WarnContext(ctx, "failed to validate any DNSKEY against DS records", slog.String("domain", domain))

		return ValidationResultBogus
	}

	// CRITICAL: Now verify the DNSKEY RRset itself using the validated KSK
	// Per RFC 4035 §5.2: The DNSKEY RRset MUST be signed by a key in the DNSKEY RRset itself
	// This allows us to trust ALL keys in the set (including ZSKs with different algorithms)
	if err := v.verifyDNSKEYRRset(dnskeyResponse.Answer, validatedKSK, domain); err != nil {
		v.logger.WarnContext(ctx, "failed to verify DNSKEY RRset", slog.String("domain", domain), log.AttrError(err))

		return ValidationResultBogus
	}

	v.logger.DebugContext(ctx, "successfully validated DNSKEY", slog.String("domain", domain))

	return ValidationResultSecure
}

// validateDNSKEY validates a DNSKEY against a DS record from parent zone
func (v *Validator) validateDNSKEY(dnskey *dns.DNSKEY, parentDS *dns.DS) error {
	// RFC 4034 §5.2: DS Algorithm field MUST match DNSKEY Algorithm field
	if dnskey.Algorithm != parentDS.Algorithm {
		return fmt.Errorf("algorithm mismatch: DNSKEY uses %d, DS expects %d",
			dnskey.Algorithm, parentDS.Algorithm)
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
// This is a convenience wrapper around findAndValidateKSK for callers that only need a bool result
//
//nolint:unparam // domain parameter used for logging, test usage pattern is acceptable
func (v *Validator) validateAnyDNSKEY(keys []*dns.DNSKEY, dsRecords []*dns.DS, domain string) bool {
	return v.findAndValidateKSK(keys, dsRecords, domain) != nil
}

// findAndValidateKSK validates DNSKEYs against DS records and returns the first validated KSK
// This function is similar to validateAnyDNSKEY but returns the validated key instead of bool
func (v *Validator) findAndValidateKSK(keys []*dns.DNSKEY, dsRecords []*dns.DS, domain string) *dns.DNSKEY {
	const REVOKE = 0x0080 // RFC 5011 §7: REVOKE flag (bit 8)

	for _, key := range keys {
		// Per RFC 4034 §2.1.1: Only validate keys with the ZONE flag (bit 7) set
		if key.Flags&dns.ZONE == 0 {
			continue
		}

		// RFC 5011 §7: DNSKEYs with REVOKE flag MUST NOT be used
		if key.Flags&REVOKE != 0 {
			continue
		}

		for _, ds := range dsRecords {
			if err := v.validateDNSKEY(key, ds); err == nil {
				v.logger.Debug("validated KSK",
					slog.String("domain", domain), slog.Int("flags", int(key.Flags)),
					slog.Int("algorithm", int(key.Algorithm)), slog.Int("keytag", int(key.KeyTag())))

				return key
			}
		}
	}

	return nil
}

// verifyDNSKEYRRset verifies the DNSKEY RRset using a validated KSK
// Per RFC 4035 §5.2: The DNSKEY RRset MUST be self-signed by a key in the set
// This validates all keys in the RRset, including ZSKs with different algorithms
func (v *Validator) verifyDNSKEYRRset(answer []dns.RR, validatedKSK *dns.DNSKEY, domain string) error {
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

	if len(dnskeyRecords) == 0 {
		return errors.New("no DNSKEY records found in answer")
	}

	if len(rrsigs) == 0 {
		return errors.New("no RRSIG records found for DNSKEY RRset")
	}

	// Find RRSIG that matches the validated KSK
	// Per RFC 4035 §2.2: For DNSKEY RRsets, the signer must equal the owner
	var matchingRRSIG *dns.RRSIG
	domainFQDN := dns.Fqdn(domain)

	for _, sig := range rrsigs {
		// Match by KeyTag, Algorithm, AND SignerName for security
		if sig.KeyTag == validatedKSK.KeyTag() &&
			sig.Algorithm == validatedKSK.Algorithm &&
			sig.SignerName == domainFQDN {
			matchingRRSIG = sig

			break
		}
	}

	if matchingRRSIG == nil {
		return fmt.Errorf("no RRSIG found for validated KSK (keytag=%d, algorithm=%d)",
			validatedKSK.KeyTag(), validatedKSK.Algorithm)
	}

	// Verify the DNSKEY RRset with the validated KSK
	// Note: We pass empty nsRecords and qname since we don't need wildcard validation for DNSKEY
	if err := v.verifyRRSIG(dnskeyRecords, matchingRRSIG, validatedKSK, nil, domain); err != nil {
		return fmt.Errorf("DNSKEY RRset signature verification failed: %w", err)
	}

	v.logger.Debug("successfully verified DNSKEY RRset",
		slog.String("domain", domain), slog.Int("keytag", int(validatedKSK.KeyTag())))

	return nil
}

// verifyAgainstTrustAnchors verifies DNSKEY records against root trust anchors
func (v *Validator) verifyAgainstTrustAnchors(ctx context.Context) ValidationResult {
	const REVOKE = 0x0080 // RFC 5011 §7: REVOKE flag (bit 8)

	// Query DNSKEY for root
	_, keys, err := v.queryDNSKEY(ctx, ".")
	if err != nil {
		v.logger.WarnContext(ctx, "failed to query root DNSKEY", log.AttrError(err))

		return ValidationResultIndeterminate
	}

	// Get trust anchors
	trustAnchors := v.trustAnchors.GetRootTrustAnchors()
	if len(trustAnchors) == 0 {
		v.logger.WarnContext(ctx, "no root trust anchors configured")

		return ValidationResultIndeterminate
	}

	// Trust anchors are DNSKEY records - validate by matching key content
	for _, key := range keys {
		// RFC 5011 §7: Skip revoked keys
		if key.Flags&REVOKE != 0 {
			v.logger.DebugContext(ctx, "skipping revoked root DNSKEY", slog.Int("keytag", int(key.KeyTag())))

			continue
		}

		for _, anchor := range trustAnchors {
			// Compare DNSKEYs directly
			if key.PublicKey == anchor.Key.PublicKey &&
				key.Algorithm == anchor.Key.Algorithm &&
				key.Flags == anchor.Key.Flags {
				v.logger.DebugContext(ctx, "successfully validated root DNSKEY against trust anchor")

				return ValidationResultSecure
			}
		}
	}

	v.logger.WarnContext(ctx, "failed to validate root DNSKEY against any trust anchor")

	return ValidationResultBogus
}

// verifyDomainAgainstTrustAnchor verifies DNSKEY records for a domain against its configured trust anchor
func (v *Validator) verifyDomainAgainstTrustAnchor(ctx context.Context, domain string) ValidationResult {
	const REVOKE = 0x0080 // RFC 5011 §7: REVOKE flag (bit 8)

	// Query DNSKEY for the domain
	_, keys, err := v.queryDNSKEY(ctx, domain)
	if err != nil {
		v.logger.WarnContext(ctx, "failed to query DNSKEY", slog.String("domain", domain), log.AttrError(err))

		return ValidationResultIndeterminate
	}

	// Get trust anchors for this domain
	trustAnchors := v.trustAnchors.GetTrustAnchors(domain)
	if len(trustAnchors) == 0 {
		v.logger.WarnContext(ctx, "no trust anchors configured for domain", slog.String("domain", domain))

		return ValidationResultIndeterminate
	}

	// Trust anchors are DNSKEY records - validate by matching key content
	for _, key := range keys {
		// Only consider keys with the Zone Key flag set
		if key.Flags&dns.ZONE == 0 {
			continue
		}

		// RFC 5011 §7: Skip revoked keys
		if key.Flags&REVOKE != 0 {
			v.logger.DebugContext(ctx, "skipping revoked DNSKEY",
				slog.String("domain", domain), slog.Int("keytag", int(key.KeyTag())))

			continue
		}

		for _, anchor := range trustAnchors {
			// Compare DNSKEYs directly
			if key.PublicKey == anchor.Key.PublicKey &&
				key.Algorithm == anchor.Key.Algorithm &&
				key.Flags == anchor.Key.Flags {
				v.logger.DebugContext(ctx, "successfully validated DNSKEY against trust anchor", slog.String("domain", domain))

				return ValidationResultSecure
			}
		}
	}

	v.logger.WarnContext(ctx, "failed to validate DNSKEY against any trust anchor", slog.String("domain", domain))

	return ValidationResultBogus
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

// validateDSRecordSignature validates a DS record RRSIG using the parent zone's DNSKEY
func (v *Validator) validateDSRecordSignature(
	ctx context.Context, domain, parentDomain string, dsRRset []dns.RR, dsRRSIG *dns.RRSIG,
) ValidationResult {
	// Get parent zone's DNSKEY to validate the DS RRSIG
	_, parentKeys, err := v.queryDNSKEY(ctx, parentDomain)
	if err != nil {
		v.logger.WarnContext(ctx, "failed to query parent DNSKEY", slog.String("parent", parentDomain), log.AttrError(err))

		return ValidationResultIndeterminate
	}

	// Find the key that matches the DS RRSIG's key tag
	var matchingParentKey *dns.DNSKEY
	for _, key := range parentKeys {
		if key.KeyTag() == dsRRSIG.KeyTag {
			matchingParentKey = key

			break
		}
	}

	if matchingParentKey == nil {
		v.logger.WarnContext(ctx, "no parent DNSKEY found for DS validation", slog.Int("keytag", int(dsRRSIG.KeyTag)))

		return ValidationResultBogus
	}

	// Verify the DS RRSIG using parent's DNSKEY
	// Note: DS records don't use wildcard validation, so pass nil/empty for those params
	if err := v.verifyRRSIG(dsRRset, dsRRSIG, matchingParentKey, nil, ""); err != nil {
		v.logger.WarnContext(ctx, "DS RRSIG verification failed", slog.String("domain", domain), log.AttrError(err))

		return ValidationResultBogus
	}

	v.logger.DebugContext(ctx, "successfully validated DS records", slog.String("domain", domain))

	return ValidationResultSecure
}

// extractAndValidateDSRecords extracts DS records from a response and validates their RRSIG
// Per RFC 4035 §5.2: "The DS RRset MUST be signed by the parent zone's DNSKEY"
func (v *Validator) extractAndValidateDSRecords(
	ctx context.Context, domain, parentDomain string, dsResponse *dns.Msg,
) ([]*dns.DS, ValidationResult) {
	// Extract DS records (may be in answer or authority section)
	dsRecords, err := extractTypedRecords[*dns.DS](dsResponse.Answer, dsResponse.Ns)
	if err != nil {
		// No DS records found - check for authenticated denial of existence
		return v.handleDSAbsence(domain, dsResponse)
	}

	// Find and validate DS RRSIG
	dsRRSIG := v.findDSRRSIG(dsResponse, domain)
	if dsRRSIG == nil {
		return nil, ValidationResultBogus
	}

	// Convert to RRset for signature verification
	dsRRset := convertDSToRRset(dsRecords)

	// Validate the DS RRSIG using parent zone's DNSKEY
	result := v.validateDSRecordSignature(ctx, domain, parentDomain, dsRRset, dsRRSIG)
	if result != ValidationResultSecure {
		return nil, result
	}

	return dsRecords, ValidationResultSecure
}

// handleDSAbsence handles the case where no DS records are found
// Per RFC 4035 §5.2: DS absent can mean:
// 1. Unsigned delegation (Insecure) - proven by NSEC/NSEC3
// 2. Missing proof (Indeterminate) - no DS and no NSEC/NSEC3
func (v *Validator) handleDSAbsence(domain string, dsResponse *dns.Msg) ([]*dns.DS, ValidationResult) {
	// Check for NSEC/NSEC3 records proving DS doesn't exist
	hasNSEC := len(extractNSECRecords(dsResponse.Ns)) > 0
	hasNSEC3 := len(extractNSEC3Records(dsResponse.Ns)) > 0

	if !hasNSEC && !hasNSEC3 {
		// No DS and no proof of absence - cannot determine if delegation is secure
		v.logger.Warn("no DS records and no NSEC/NSEC3 proof", slog.String("domain", domain))

		return nil, ValidationResultIndeterminate
	}

	// Validate NSEC/NSEC3 proof that DS doesn't exist
	validationResult := v.validateDSAbsenceProof(domain, dsResponse, hasNSEC)

	if validationResult == ValidationResultSecure || validationResult == ValidationResultInsecure {
		// Authenticated denial of existence OR NSEC3 opt-out - this is an unsigned delegation
		v.logger.Debug("validated NSEC/NSEC3 DS-absence proof, insecure delegation", slog.String("domain", domain))

		return nil, ValidationResultInsecure
	}

	// NSEC/NSEC3 validation failed - could be an attack
	v.logger.Warn("NSEC/NSEC3 records present but failed to prove DS absence", slog.String("domain", domain))

	return nil, ValidationResultBogus
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
			v.logger.Warn("NSEC DS-absence proof does not assert an insecure delegation", slog.String("domain", domain))

			return ValidationResultBogus
		}

		return v.validateNSECNODATA(nsecRecords, domain, dns.TypeDS)
	}

	// Validate NSEC3 proof of DS absence (NODATA proof)
	return v.validateNSEC3DenialOfExistence(dsResponse, dsQuestion)
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

	v.logger.Warn("no RRSIG found for DS records", slog.String("domain", domain))

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
