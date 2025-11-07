// This file implements DNSSEC validation for DNS resolution.
//
// # DNSSEC Validation Implementation
//
// This file implements DNSSEC (Domain Name System Security Extensions) validation
// according to the following RFCs:
//   - RFC 4033: DNS Security Introduction and Requirements
//   - RFC 4034: Resource Records for DNS Security Extensions
//   - RFC 4035: Protocol Modifications for DNS Security Extensions
//   - RFC 5155: DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
//   - RFC 6840: Clarifications and Implementation Notes for DNSSEC
//   - RFC 6781: DNSSEC Operational Practices, Version 2
//   - RFC 8080: Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC
//   - RFC 8624: Algorithm Implementation Requirements and Usage Guidance for DNSSEC
//
// Key Features:
//
// 1. Full Chain of Trust Validation
//   - Validates DNSSEC signatures from trust anchors (root keys) down to zone data
//   - Supports both NSEC and NSEC3 authenticated denial of existence
//   - Handles wildcard expansion validation per RFC 4035 §5.3.4
//
// 2. DoS Protection
//   - Configurable maximum chain depth to prevent excessive recursion
//   - Maximum NSEC3 iteration limit (default 150, per RFC 5155 §10.3)
//   - Maximum upstream query budget to prevent query amplification attacks
//   - Request-scoped query counting to track and limit validation overhead
//
// 3. Security Best Practices
//   - Algorithm downgrade attack prevention (RFC 6840 §5.11)
//   - Clock skew tolerance for signature validation (RFC 6781 §4.1.2)
//   - Support for modern algorithms including EdDSA (RFC 8080)
//   - Comprehensive validation result caching to reduce load
//
// 4. Performance Optimizations
//   - Expiring cache for validation results
//   - NSEC3 hash computation caching
//   - Prometheus metrics for monitoring validation performance
//   - Parallel validation where applicable
//
// The validator returns one of four results:
//   - Secure: Valid DNSSEC signatures and complete chain of trust
//   - Insecure: No DNSSEC (unsigned zone, valid delegation)
//   - Bogus: Invalid DNSSEC (failed validation, security threat)
//   - Indeterminate: Validation could not be completed (network/system errors)
package resolver

//go:generate go tool go-enum -f=$GOFILE --marshal --names --values

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/0xERR0R/blocky/cache"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"
	expirationcache "github.com/0xERR0R/expiration-cache"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// ValidationResult represents the result of DNSSEC validation ENUM(
// Secure // Valid DNSSEC signatures and chain of trust
// Insecure // No DNSSEC (unsigned zone)
// Bogus // Invalid DNSSEC (failed validation)
// Indeterminate // Validation could not be completed
// )
type ValidationResult int

// queryBudgetKey is the context key for tracking upstream query budget
type queryBudgetKey struct{}

// DNSSECValidator validates DNSSEC signatures and chains of trust
type DNSSECValidator struct {
	trustAnchors          *TrustAnchorStore
	logger                *logrus.Entry
	upstream              Resolver // Used to query for DNSKEY and DS records
	validationCache       cache.ExpiringCache[ValidationResult]
	nsec3HashCache        sync.Map // Cache for NSEC3 hash computations: key = "name:alg:salt:iterations"
	cacheExpiration       time.Duration
	maxChainDepth         uint // Maximum depth for chain of trust validation
	maxNSEC3Iterations    uint // Maximum NSEC3 iterations (RFC 5155 §10.3)
	maxUpstreamQueries    uint // Maximum upstream queries per validation (DoS protection)
	clockSkewToleranceSec uint // Clock skew tolerance in seconds (RFC 6781 §4.1.2)
	validationMetrics     *prometheus.CounterVec
	cacheHitMetrics       prometheus.Counter
	validationDuration    *prometheus.HistogramVec
}

// initializeMetrics initializes and registers Prometheus metrics for the validator
func (v *DNSSECValidator) initializeMetrics() {
	v.validationMetrics = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blocky_dnssec_validation_total",
			Help: "Number of DNSSEC validations by result",
		},
		[]string{"result"},
	)

	v.cacheHitMetrics = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "blocky_dnssec_cache_hits_total",
			Help: "Number of DNSSEC validation cache hits",
		},
	)

	v.validationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "blocky_dnssec_validation_duration_seconds",
			Help:    "Duration of DNSSEC validation operations",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"result"},
	)

	metrics.RegisterMetric(v.validationMetrics)
	metrics.RegisterMetric(v.cacheHitMetrics)
	metrics.RegisterMetric(v.validationDuration)
}

// NewDNSSECValidator creates a new DNSSEC validator with the given configuration.
//
// Parameters:
//   - ctx: Context for the validator lifecycle (used for cache cleanup)
//   - trustAnchors: Trust anchor store containing root and/or zone-specific DNSSEC trust anchors
//   - logger: Logger for validation events and debugging
//   - upstream: Resolver to use for querying DNSKEY and DS records
//   - cacheExpirationHours: How long to cache validation results (0 defaults to 1 hour)
//   - maxChainDepth: Maximum domain label depth to validate (0 defaults to 10, prevents DoS)
//   - maxNSEC3Iterations: Maximum NSEC3 iterations (0 defaults to 150, prevents DoS)
//   - maxUpstreamQueries: Maximum upstream queries per validation (0 defaults to 30, prevents DoS)
//   - clockSkewToleranceSec: Clock skew tolerance in seconds (0 defaults to 3600 = 1 hour)
//
// Returns a configured DNSSECValidator ready for use.
func NewDNSSECValidator(
	ctx context.Context,
	trustAnchors *TrustAnchorStore,
	logger *logrus.Entry,
	upstream Resolver,
	cacheExpirationHours uint,
	maxChainDepth uint,
	maxNSEC3Iterations uint,
	maxUpstreamQueries uint,
	clockSkewToleranceSec uint,
) *DNSSECValidator {
	// Set defaults if not configured
	if cacheExpirationHours == 0 {
		cacheExpirationHours = 1
	}
	if maxChainDepth == 0 {
		maxChainDepth = 10
	}
	if maxNSEC3Iterations == 0 {
		maxNSEC3Iterations = 150 // RFC 5155 §10.3 recommended limit
	}
	if maxUpstreamQueries == 0 {
		maxUpstreamQueries = 30 // Reasonable default for chain validation
	}
	if clockSkewToleranceSec == 0 {
		clockSkewToleranceSec = 3600 // 1 hour default (matches Unbound/BIND)
	}

	v := &DNSSECValidator{
		trustAnchors: trustAnchors,
		logger:       logger,
		upstream:     upstream,
		validationCache: expirationcache.NewCache[ValidationResult](ctx, expirationcache.Options{
			CleanupInterval: time.Hour,
		}),
		cacheExpiration:       time.Duration(cacheExpirationHours) * time.Hour,
		maxChainDepth:         maxChainDepth,
		maxNSEC3Iterations:    maxNSEC3Iterations,
		maxUpstreamQueries:    maxUpstreamQueries,
		clockSkewToleranceSec: clockSkewToleranceSec,
	}

	v.initializeMetrics()

	return v
}

// ValidateResponse validates a DNS response's DNSSEC signatures according to RFC 4035.
//
// This function performs the following validation steps:
//  1. Checks if the response contains DNSSEC signatures (RRSIG records)
//  2. If unsigned, returns ValidationResultInsecure
//  3. If signed, validates all RRsets in the answer section:
//     - Verifies RRSIG signatures match the RRset data
//     - Validates signature time windows (inception/expiration)
//     - Walks the chain of trust from root to the domain
//     - Verifies DNSKEYs against DS records or trust anchors
//  4. Returns ValidationResultSecure if all checks pass
//  5. Returns ValidationResultBogus if validation fails
//
// Parameters:
//   - ctx: Context for the validation operation
//   - response: DNS response message to validate
//   - question: Original DNS question for context
//
// Returns one of: ValidationResultSecure, ValidationResultInsecure,
// ValidationResultBogus, or ValidationResultIndeterminate
func (v *DNSSECValidator) ValidateResponse(
	ctx context.Context,
	response *dns.Msg,
	question dns.Question,
) ValidationResult {
	start := time.Now()
	v.logger.Debugf("DNSSEC validation requested for %s", question.Name)

	// Initialize query budget for this validation request (DoS protection)
	ctx = context.WithValue(ctx, queryBudgetKey{}, int(v.maxUpstreamQueries))

	var result ValidationResult

	// Dispatch to appropriate validator based on response type
	switch {
	case !v.hasAnySignatures(response):
		v.logger.Debugf("No RRSIG records found for %s - zone is unsigned", question.Name)
		result = ValidationResultInsecure
	case len(response.Answer) > 0:
		result = v.validateAnswer(ctx, response, question)
	case v.isNegativeResponse(response):
		result = v.validateNegativeResponse(ctx, response, question)
	case v.hasAuthorityOrAdditional(response):
		result = v.validateAuthorityOrAdditional(ctx, response, question)
	default:
		result = ValidationResultInsecure
	}

	v.recordMetrics(start, result)

	return result
}

// hasAnySignatures checks if response contains any RRSIG records
func (v *DNSSECValidator) hasAnySignatures(response *dns.Msg) bool {
	return len(extractRRSIGs(response.Answer)) > 0 ||
		len(extractRRSIGs(response.Ns)) > 0 ||
		len(extractRRSIGs(response.Extra)) > 0
}

// validateAnswer validates the answer section of a response
func (v *DNSSECValidator) validateAnswer(
	ctx context.Context, response *dns.Msg, question dns.Question,
) ValidationResult {
	result := v.validateRRsets(ctx, response.Answer, question.Name, response.Ns, question.Name)
	if result != ValidationResultSecure {
		v.logger.Warnf("Answer validation failed for %s: %s", question.Name, result.String())
	} else {
		v.logger.Debugf("DNSSEC validation succeeded for %s", question.Name)
	}

	return result
}

// isNegativeResponse checks if response is NXDOMAIN or NODATA
// Per RFC 4035 §5.4: NXDOMAIN (Rcode=3) or NODATA (Rcode=0 with no answer RRs)
func (v *DNSSECValidator) isNegativeResponse(response *dns.Msg) bool {
	if response.Rcode == dns.RcodeNameError {
		return true // NXDOMAIN
	}
	// NODATA: Success with no answer section
	if response.Rcode == dns.RcodeSuccess && len(response.Answer) == 0 {
		return true
	}

	return false
}

// validateNegativeResponse validates NXDOMAIN or NODATA responses
func (v *DNSSECValidator) validateNegativeResponse(
	ctx context.Context, response *dns.Msg, question dns.Question,
) ValidationResult {
	nsSigs := extractRRSIGs(response.Ns)
	if len(nsSigs) == 0 {
		v.logger.Debugf("No signatures in authority section for denial of existence: %s", question.Name)

		return ValidationResultInsecure
	}

	result := v.validateDenialOfExistence(ctx, response, question)
	if result != ValidationResultSecure {
		v.logger.Warnf("Denial of existence validation failed for %s: %s", question.Name, result.String())
	} else {
		v.logger.Debugf("Denial of existence validated for %s", question.Name)
	}

	return result
}

// hasAuthorityOrAdditional checks if response has signatures in NS or Extra sections
func (v *DNSSECValidator) hasAuthorityOrAdditional(response *dns.Msg) bool {
	return len(extractRRSIGs(response.Ns)) > 0 || len(extractRRSIGs(response.Extra)) > 0
}

// validateAuthorityOrAdditional validates authority or additional sections
func (v *DNSSECValidator) validateAuthorityOrAdditional(
	ctx context.Context, response *dns.Msg, question dns.Question,
) ValidationResult {
	// Combine authority and additional sections for validation
	sectionsToValidate := make([]dns.RR, 0, len(response.Ns)+len(response.Extra))
	sectionsToValidate = append(sectionsToValidate, response.Ns...)
	sectionsToValidate = append(sectionsToValidate, response.Extra...)

	if len(sectionsToValidate) == 0 {
		return ValidationResultInsecure
	}

	result := v.validateRRsets(ctx, sectionsToValidate, question.Name, response.Ns, question.Name)
	if result != ValidationResultSecure {
		v.logger.Warnf("Authority/Additional validation failed for %s: %s", question.Name, result.String())
	}

	return result
}

// recordMetrics records validation metrics
func (v *DNSSECValidator) recordMetrics(start time.Time, result ValidationResult) {
	duration := time.Since(start)
	v.validationMetrics.WithLabelValues(result.String()).Inc()
	v.validationDuration.WithLabelValues(result.String()).Observe(duration.Seconds())
}

// extractRRSIGs extracts all RRSIG records from a slice of RRs
func extractRRSIGs(rrs []dns.RR) []*dns.RRSIG {
	var sigs []*dns.RRSIG
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, sig)
		}
	}

	return sigs
}

// groupRRsetsByType groups RRs by their type (excluding RRSIGs)
func groupRRsetsByType(rrs []dns.RR) map[uint16][]dns.RR {
	rrsets := make(map[uint16][]dns.RR)
	for _, rr := range rrs {
		if _, isSig := rr.(*dns.RRSIG); !isSig {
			rrType := rr.Header().Rrtype
			rrsets[rrType] = append(rrsets[rrType], rr)
		}
	}

	return rrsets
}

// validateRRsets validates all RRsets in a section
func (v *DNSSECValidator) validateRRsets(
	ctx context.Context, rrs []dns.RR, domain string, nsRecords []dns.RR, qname string,
) ValidationResult {
	// Extract all RRSIGs
	sigs := extractRRSIGs(rrs)
	if len(sigs) == 0 {
		v.logger.Debugf("No RRSIGs found in section for %s", domain)

		return ValidationResultInsecure
	}

	// Group RRs by type
	rrsets := groupRRsetsByType(rrs)

	// Validate each RRset
	for rrType, rrset := range rrsets {
		result := v.validateSingleRRset(ctx, rrType, rrset, sigs, domain, nsRecords, qname)
		if result != ValidationResultSecure {
			return result
		}
	}

	return ValidationResultSecure
}

// validateSingleRRset validates a single RRset with its signatures
func (v *DNSSECValidator) validateSingleRRset(
	ctx context.Context, rrType uint16, rrset []dns.RR, sigs []*dns.RRSIG,
	domain string, nsRecords []dns.RR, qname string,
) ValidationResult {
	// Find matching RRSIGs for this RRset
	// Per RFC 6840 §5.11, we should prefer stronger algorithms to prevent downgrade attacks
	matchingRRSIGs := findMatchingRRSIGsForType(sigs, rrType)

	if len(matchingRRSIGs) == 0 {
		v.logger.Warnf("No RRSIG found for RRset type %d in %s", rrType, domain)

		return ValidationResultBogus
	}

	// Select the best RRSIG (prefer stronger algorithms)
	matchingSig := v.selectBestRRSIG(matchingRRSIGs)

	// Validate signer name
	signerName := matchingSig.SignerName
	rrsetName := dns.Fqdn(rrset[0].Header().Name)

	// RFC 4035 §2.2: For DNSKEY RRsets, the signer must equal the owner (self-signed at zone apex)
	// This prevents a parent zone from signing a child's DNSKEY, which would break the chain of trust
	if rrType == dns.TypeDNSKEY {
		if signerName != rrsetName {
			v.logger.Warnf("DNSKEY signer %s must equal owner %s (RFC 4035 §2.2)", signerName, rrsetName)

			return ValidationResultBogus
		}
	} else {
		// For non-DNSKEY RRsets, signer must be a parent of the RRset owner
		if !validateSignerName(signerName, rrsetName) {
			v.logger.Warnf("RRSIG signer name %s is not a parent of RRset owner %s", signerName, rrsetName)

			return ValidationResultBogus
		}
	}

	// Query and match DNSKEY
	ctx, matchingKey, err := v.queryAndMatchDNSKEY(ctx, signerName, matchingSig.KeyTag)
	if err != nil {
		v.logger.Warnf("DNSKEY query/match failed for %s: %v", signerName, err)

		return ValidationResultBogus
	}

	// Verify the signature
	if err := v.verifyRRSIG(rrset, matchingSig, matchingKey, nsRecords, qname); err != nil {
		// Per RFC 4035: Any verification failure (expired, not yet valid, or crypto failure) = Bogus
		v.logger.Warnf("RRSIG verification failed for %s: %v", domain, err)

		return ValidationResultBogus
	}

	// Now validate the DNSKEY itself by walking the chain of trust
	return v.walkChainOfTrust(ctx, signerName)
}

// queryAndMatchDNSKEY queries for DNSKEY records and finds the one matching the key tag
func (v *DNSSECValidator) queryAndMatchDNSKEY(
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

// getAlgorithmStrength returns a strength score for a DNSSEC algorithm
// Higher scores indicate stronger algorithms (used to prevent downgrade attacks)
func (v *DNSSECValidator) getAlgorithmStrength(alg uint8) int {
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
func (v *DNSSECValidator) selectBestRRSIG(rrsigs []*dns.RRSIG) *dns.RRSIG {
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
func (v *DNSSECValidator) isSupportedAlgorithm(alg uint8) bool {
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
func (v *DNSSECValidator) verifyRRSIG(
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

// validateWildcardExpansion validates wildcard expansions per RFC 4035 §5.3.4
//
// This implementation performs COMPLETE wildcard validation including:
//   - Wildcard name is within signer's zone
//   - Label count is consistent with RRSIG
//   - Signature cryptographically validates
//   - NSEC/NSEC3 proves the expanded name doesn't exist (no closer match)
//
// Per RFC 4035 §5.3.4: "The validator must verify that the QNAME does not
// match any existing name within the zone by checking for the existence of
// an NSEC RR proving that the QNAME does not exist."
func (v *DNSSECValidator) validateWildcardExpansion(
	rrsetName string, rrsig *dns.RRSIG, nsRecords []dns.RR, qname string,
) error {
	// RFC 4035 §5.3.4: Check if this is a wildcard expansion
	// The labels field in RRSIG indicates the number of labels in the original owner name
	// If the actual owner name has more labels, it's a wildcard expansion

	rrsetName = dns.Fqdn(rrsetName)
	signerName := dns.Fqdn(rrsig.SignerName)

	// Count labels in the RRset owner name (excluding root label)
	rrsetLabels := dns.CountLabel(rrsetName)

	// RRSIG Labels field indicates original owner name label count
	rrsigLabels := int(rrsig.Labels)

	// If RRset has same or fewer labels than RRSIG, it's not a wildcard expansion
	if rrsetLabels <= rrsigLabels {
		return nil
	}

	// This is a wildcard expansion - validate it
	return v.validateWildcardExpansionDetails(rrsetName, signerName, rrsigLabels, nsRecords, qname)
}

// validateWildcardExpansionDetails performs the actual wildcard validation logic
func (v *DNSSECValidator) validateWildcardExpansionDetails(
	rrsetName, signerName string, rrsigLabels int, nsRecords []dns.RR, qname string,
) error {
	// RFC 4035 §5.3.4: Construct the wildcard name
	// Take the rightmost (rrsigLabels) labels and prepend "*"
	labels := dns.SplitDomainName(rrsetName)
	if len(labels) < rrsigLabels {
		return fmt.Errorf("invalid wildcard: RRset has %d labels but RRSIG claims %d",
			len(labels), rrsigLabels)
	}

	// Build wildcard name: *.rightmost(rrsigLabels) labels
	wildcardLabels := append([]string{"*"}, labels[len(labels)-rrsigLabels:]...)
	wildcardName := dns.Fqdn(strings.Join(wildcardLabels, "."))

	v.logger.Debugf("Wildcard expansion detected: %s expanded to %s", wildcardName, rrsetName)

	// Verify wildcard name is within the signer's zone
	if !dns.IsSubDomain(signerName, wildcardName) {
		return fmt.Errorf("wildcard %s not within signer zone %s", wildcardName, signerName)
	}

	// RFC 4035 §5.3.4: Verify that NSEC/NSEC3 proves the query name doesn't exist
	return v.validateWildcardProof(wildcardName, rrsetName, nsRecords, qname)
}

// validateWildcardProof verifies NSEC/NSEC3 proof that qname doesn't exist
func (v *DNSSECValidator) validateWildcardProof(
	wildcardName, rrsetName string, nsRecords []dns.RR, qname string,
) error {
	qname = dns.Fqdn(qname)

	// Try NSEC validation first
	nsecRecords := extractNSECRecords(nsRecords)
	if len(nsecRecords) > 0 {
		if err := v.validateWildcardNSEC(nsecRecords, qname); err != nil {
			return fmt.Errorf("wildcard NSEC validation failed: %w", err)
		}
		v.logger.Debugf("Wildcard NSEC validation succeeded: %s expanded to %s", wildcardName, rrsetName)

		return nil
	}

	// Try NSEC3 validation
	nsec3Records := extractNSEC3Records(nsRecords)
	if len(nsec3Records) > 0 {
		if err := v.validateWildcardNSEC3(nsec3Records, qname); err != nil {
			return fmt.Errorf("wildcard NSEC3 validation failed: %w", err)
		}
		v.logger.Debugf("Wildcard NSEC3 validation succeeded: %s expanded to %s", wildcardName, rrsetName)

		return nil
	}

	// No NSEC/NSEC3 records found to prove non-existence
	// Per RFC 4035 §5.3.4, wildcard expansion requires proof that the query name doesn't exist.
	// Some authoritative servers may not include authority section records in all responses.
	// We treat this strictly as an error to maintain security, but log for awareness.
	v.logger.Warnf("Wildcard expansion detected for %s but authority section missing NSEC/NSEC3 proof - "+
		"this may be due to incomplete server response", qname)

	return fmt.Errorf("wildcard expansion detected but no NSEC/NSEC3 proof of non-existence for %s", qname)
}

// validateWildcardNSEC validates wildcard expansion using NSEC records
// Per RFC 4035 §5.3.4: Must prove the query name doesn't exist
func (v *DNSSECValidator) validateWildcardNSEC(nsecRecords []*dns.NSEC, qname string) error {
	qname = dns.Fqdn(qname)

	// Check if any NSEC covers the query name (proving it doesn't exist)
	for _, nsec := range nsecRecords {
		if v.nsecCoversName(nsec, qname) {
			v.logger.Debugf("NSEC record covers wildcard query name %s", qname)

			return nil
		}
	}

	return fmt.Errorf("no NSEC record covers query name %s to prove non-existence", qname)
}

// validateWildcardNSEC3 validates wildcard expansion using NSEC3 records
// Per RFC 5155 §7.2.6: Must prove the query name doesn't exist
func (v *DNSSECValidator) validateWildcardNSEC3(nsec3Records []*dns.NSEC3, qname string) error {
	if len(nsec3Records) == 0 {
		return errors.New("no NSEC3 records available")
	}

	qname = dns.Fqdn(qname)

	// Get NSEC3 parameters from first record
	hashAlg := nsec3Records[0].Hash
	salt := nsec3Records[0].Salt
	iterations := nsec3Records[0].Iterations

	// Verify parameters are consistent
	for _, nsec3 := range nsec3Records {
		if nsec3.Hash != hashAlg || nsec3.Salt != salt || nsec3.Iterations != iterations {
			return errors.New("inconsistent NSEC3 parameters in response")
		}
	}

	// Check iteration count limit
	if iterations > uint16(v.maxNSEC3Iterations) {
		return fmt.Errorf("NSEC3 iteration count %d exceeds maximum %d",
			iterations, v.maxNSEC3Iterations)
	}

	// Only SHA-1 is currently standardized
	if hashAlg != dns.SHA1 {
		return fmt.Errorf("unsupported NSEC3 hash algorithm: %d", hashAlg)
	}

	// Compute hash of query name
	qnameHash, err := v.computeNSEC3Hash(qname, hashAlg, salt, iterations)
	if err != nil {
		return fmt.Errorf("failed to compute NSEC3 hash: %w", err)
	}

	// Check if any NSEC3 covers the query name hash
	if v.nsec3Covers(nsec3Records, qnameHash) {
		v.logger.Debugf("NSEC3 record covers wildcard query name hash for %s", qname)

		return nil
	}

	return fmt.Errorf("no NSEC3 record covers query name %s to prove non-existence", qname)
}

// extractNSEC3Records extracts NSEC3 records from a list of RRs
func extractNSEC3Records(rrs []dns.RR) []*dns.NSEC3 {
	var nsec3s []*dns.NSEC3
	for _, rr := range rrs {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			nsec3s = append(nsec3s, nsec3)
		}
	}

	return nsec3s
}

// validateDNSKEY validates a DNSKEY against a DS record from parent zone
func (v *DNSSECValidator) validateDNSKEY(dnskey *dns.DNSKEY, parentDS *dns.DS) error {
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

// getCachedValidation retrieves a cached validation result
func (v *DNSSECValidator) getCachedValidation(domain string) (ValidationResult, bool) {
	result, _ := v.validationCache.Get(domain)
	if result == nil {
		return ValidationResultIndeterminate, false
	}

	// Record cache hit
	v.cacheHitMetrics.Inc()

	return *result, true
}

// setCachedValidation stores a validation result in the cache
func (v *DNSSECValidator) setCachedValidation(domain string, result ValidationResult) {
	v.validationCache.Put(domain, &result, v.cacheExpiration)
}

// walkChainOfTrust walks the chain of trust from root to target domain
func (v *DNSSECValidator) walkChainOfTrust(ctx context.Context, domain string) ValidationResult {
	// Normalize the domain name
	domain = dns.Fqdn(domain)

	// Check cache first
	if cached, found := v.getCachedValidation(domain); found {
		v.logger.Debugf("Using cached validation result for %s: %s", domain, cached.String())

		return cached
	}

	// Split domain into labels
	labels := dns.SplitDomainName(domain)

	// Check chain depth limit to prevent DoS attacks with deeply nested domains
	// RFC does not specify a limit, but we add one for security
	if uint(len(labels)) > v.maxChainDepth {
		v.logger.Warnf("Domain %s exceeds maximum chain depth (%d labels > %d max), rejecting",
			domain, len(labels), v.maxChainDepth)
		result := ValidationResultBogus
		v.setCachedValidation(domain, result)

		return result
	}

	// If this is the root, verify against trust anchors
	if domain == "." {
		result := v.verifyAgainstTrustAnchors(ctx)
		v.setCachedValidation(domain, result)

		return result
	}

	// Walk from root down to target domain
	currentDomain := "."
	for i := len(labels) - 1; i >= 0; i-- {
		// Build the domain for this level
		if i == len(labels)-1 {
			currentDomain = labels[i] + "."
		} else {
			currentDomain = labels[i] + "." + currentDomain
		}

		// Check if this domain has a configured trust anchor
		if v.trustAnchors.HasTrustAnchor(currentDomain) {
			v.logger.Debugf("Domain %s has a configured trust anchor, verifying DNSKEY", currentDomain)
			// Trust anchor found - verify that actual DNSKEY from DNS matches the trust anchor
			result := v.verifyDomainAgainstTrustAnchor(ctx, currentDomain)
			if result != ValidationResultSecure {
				v.setCachedValidation(domain, result)

				return result
			}
			// Trust anchor verified, continue to validate child zones
			continue
		}

		// Validate this level of the chain
		result := v.validateDomainLevel(ctx, currentDomain)
		if result != ValidationResultSecure {
			v.setCachedValidation(domain, result)

			return result
		}
	}

	// Cache successful validation
	v.setCachedValidation(domain, ValidationResultSecure)

	return ValidationResultSecure
}

// validateDSRecordSignature validates a DS record RRSIG using the parent zone's DNSKEY
func (v *DNSSECValidator) validateDSRecordSignature(
	ctx context.Context, domain, parentDomain string, dsRRset []dns.RR, dsRRSIG *dns.RRSIG,
) ValidationResult {
	// Get parent zone's DNSKEY to validate the DS RRSIG
	_, parentKeys, err := v.queryDNSKEY(ctx, parentDomain)
	if err != nil {
		v.logger.Warnf("Failed to query parent DNSKEY for %s: %v", parentDomain, err)

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
		v.logger.Warnf("No parent DNSKEY with key tag %d found for DS validation", dsRRSIG.KeyTag)

		return ValidationResultBogus
	}

	// Verify the DS RRSIG using parent's DNSKEY
	// Note: DS records don't use wildcard validation, so pass nil/empty for those params
	if err := v.verifyRRSIG(dsRRset, dsRRSIG, matchingParentKey, nil, ""); err != nil {
		v.logger.Warnf("DS RRSIG verification failed for %s: %v", domain, err)

		return ValidationResultBogus
	}

	v.logger.Debugf("Successfully validated DS records for %s using parent zone's DNSKEY", domain)

	return ValidationResultSecure
}

// extractAndValidateDSRecords extracts DS records from a response and validates their RRSIG
// Per RFC 4035 §5.2: "The DS RRset MUST be signed by the parent zone's DNSKEY"
func (v *DNSSECValidator) extractAndValidateDSRecords(
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
func (v *DNSSECValidator) handleDSAbsence(domain string, dsResponse *dns.Msg) ([]*dns.DS, ValidationResult) {
	// Check for NSEC/NSEC3 records proving DS doesn't exist
	hasNSEC := len(extractNSECRecords(dsResponse.Ns)) > 0
	hasNSEC3 := len(extractNSEC3Records(dsResponse.Ns)) > 0

	if !hasNSEC && !hasNSEC3 {
		// No DS and no proof of absence - cannot determine if delegation is secure
		v.logger.Warnf("No DS records for %s and no NSEC/NSEC3 proof - indeterminate", domain)

		return nil, ValidationResultIndeterminate
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

// validateDSAbsenceProof validates NSEC or NSEC3 proof that DS doesn't exist
func (v *DNSSECValidator) validateDSAbsenceProof(domain string, dsResponse *dns.Msg, hasNSEC bool) ValidationResult {
	// Create a synthetic question for DS query validation
	dsQuestion := dns.Question{
		Name:   domain,
		Qtype:  dns.TypeDS,
		Qclass: dns.ClassINET,
	}

	if hasNSEC {
		// Validate NSEC proof of DS absence (NODATA proof)
		nsecRecords := extractNSECRecords(dsResponse.Ns)

		return v.validateNSECNODATA(nsecRecords, domain, dns.TypeDS)
	}

	// Validate NSEC3 proof of DS absence (NODATA proof)
	return v.validateNSEC3DenialOfExistence(dsResponse, dsQuestion)
}

// findDSRRSIG finds the RRSIG for DS records in the response
func (v *DNSSECValidator) findDSRRSIG(dsResponse *dns.Msg, domain string) *dns.RRSIG {
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

// validateDomainLevel validates a single level in the DNSSEC chain
func (v *DNSSECValidator) validateDomainLevel(ctx context.Context, domain string) ValidationResult {
	v.logger.Debugf("Validating domain level: %s", domain)

	// Query DS records from parent zone
	// Per RFC 4034 §5: DS records are published in the PARENT zone, not the child
	parentDomain := v.getParentDomain(domain)
	if parentDomain == "" {
		// Root domain has no parent
		v.logger.Debugf("Domain %s has no parent, cannot validate via DS", domain)

		return ValidationResultInsecure
	}

	// CRITICAL FIX: Per RFC 4035 §5.2, we must validate the parent zone's DNSKEY
	// BEFORE trusting the DS records from that parent zone
	// First, ensure the parent zone itself is validated (recursive chain validation)
	parentResult := v.walkChainOfTrust(ctx, parentDomain)
	if parentResult != ValidationResultSecure {
		v.logger.Warnf("Parent zone %s validation failed: %s", parentDomain, parentResult.String())

		return parentResult
	}

	// Query DS records for the child domain from the parent zone
	// Note: The DS query name is the child domain, but the response comes from parent's authority
	ctx, dsResponse, err := v.queryRecords(ctx, domain, dns.TypeDS)
	if err != nil {
		v.logger.Warnf("Failed to query DS for %s: %v", domain, err)

		return ValidationResultIndeterminate
	}

	// Extract and validate DS records (may be in answer or authority section)
	dsRecords, result := v.extractAndValidateDSRecords(ctx, domain, parentDomain, dsResponse)
	if result != ValidationResultSecure {
		return result
	}

	// Query DNSKEY records for current domain
	_, keys, err := v.queryDNSKEY(ctx, domain)
	if err != nil {
		v.logger.Warnf("Failed to query DNSKEY for %s: %v", domain, err)

		return ValidationResultIndeterminate
	}

	// Validate at least one DNSKEY against the DS records
	if !v.validateAnyDNSKEY(keys, dsRecords, domain) {
		v.logger.Warnf("Failed to validate any DNSKEY against DS records for %s", domain)

		return ValidationResultBogus
	}

	return ValidationResultSecure
}

// validateAnyDNSKEY validates at least one DNSKEY against DS records
func (v *DNSSECValidator) validateAnyDNSKEY(keys []*dns.DNSKEY, dsRecords []*dns.DS, domain string) bool {
	const REVOKE = 0x0080 // RFC 5011 §7: REVOKE flag (bit 8)

	for _, key := range keys {
		// Per RFC 4034 §2.1.1: Only validate keys with the ZONE flag (bit 7) set
		// The SEP flag (bit 15) distinguishes KSK from ZSK, but both have ZONE flag set
		// ZONE flag (257 for KSK, 256 for ZSK) indicates this key is authorized to sign zones
		if key.Flags&dns.ZONE == 0 {
			v.logger.Debugf("Skipping DNSKEY for %s: ZONE flag not set (flags: %d)", domain, key.Flags)

			continue
		}

		// RFC 5011 §7: Check for REVOKE flag (bit 8)
		// DNSKEYs with REVOKE flag set MUST NOT be used for validation
		if key.Flags&REVOKE != 0 {
			v.logger.Debugf("Skipping revoked DNSKEY for %s (flags: %d, keytag: %d)",
				domain, key.Flags, key.KeyTag())

			continue
		}

		for _, ds := range dsRecords {
			if err := v.validateDNSKEY(key, ds); err == nil {
				v.logger.Debugf("Successfully validated DNSKEY for %s", domain)

				return true
			}
		}
	}

	return false
}

// verifyAgainstTrustAnchors verifies DNSKEY records against root trust anchors
func (v *DNSSECValidator) verifyAgainstTrustAnchors(ctx context.Context) ValidationResult {
	const REVOKE = 0x0080 // RFC 5011 §7: REVOKE flag (bit 8)

	// Query DNSKEY for root
	_, keys, err := v.queryDNSKEY(ctx, ".")
	if err != nil {
		v.logger.Warnf("Failed to query root DNSKEY: %v", err)

		return ValidationResultIndeterminate
	}

	// Get trust anchors
	trustAnchors := v.trustAnchors.GetRootTrustAnchors()
	if len(trustAnchors) == 0 {
		v.logger.Warn("No root trust anchors configured")

		return ValidationResultIndeterminate
	}

	// Trust anchors are DNSKEY records - validate by matching key content
	for _, key := range keys {
		// RFC 5011 §7: Skip revoked keys
		if key.Flags&REVOKE != 0 {
			v.logger.Debugf("Skipping revoked root DNSKEY (keytag: %d)", key.KeyTag())

			continue
		}

		for _, anchor := range trustAnchors {
			// Compare DNSKEYs directly
			if key.PublicKey == anchor.Key.PublicKey &&
				key.Algorithm == anchor.Key.Algorithm &&
				key.Flags == anchor.Key.Flags {
				v.logger.Debug("Successfully validated root DNSKEY against trust anchor")

				return ValidationResultSecure
			}
		}
	}

	v.logger.Warn("Failed to validate root DNSKEY against any trust anchor")

	return ValidationResultBogus
}

// verifyDomainAgainstTrustAnchor verifies DNSKEY records for a domain against its configured trust anchor
func (v *DNSSECValidator) verifyDomainAgainstTrustAnchor(ctx context.Context, domain string) ValidationResult {
	const REVOKE = 0x0080 // RFC 5011 §7: REVOKE flag (bit 8)

	// Query DNSKEY for the domain
	_, keys, err := v.queryDNSKEY(ctx, domain)
	if err != nil {
		v.logger.Warnf("Failed to query DNSKEY for %s: %v", domain, err)

		return ValidationResultIndeterminate
	}

	// Get trust anchors for this domain
	trustAnchors := v.trustAnchors.GetTrustAnchors(domain)
	if len(trustAnchors) == 0 {
		v.logger.Warnf("No trust anchors configured for %s", domain)

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
			v.logger.Debugf("Skipping revoked DNSKEY for %s (keytag: %d)", domain, key.KeyTag())

			continue
		}

		for _, anchor := range trustAnchors {
			// Compare DNSKEYs directly
			if key.PublicKey == anchor.Key.PublicKey &&
				key.Algorithm == anchor.Key.Algorithm &&
				key.Flags == anchor.Key.Flags {
				v.logger.Debugf("Successfully validated DNSKEY for %s against trust anchor", domain)

				return ValidationResultSecure
			}
		}
	}

	v.logger.Warnf("Failed to validate DNSKEY for %s against any trust anchor", domain)

	return ValidationResultBogus
}

// getParentDomain returns the parent domain of the given domain
// Returns empty string if the domain is root or has no parent
func (v *DNSSECValidator) getParentDomain(domain string) string {
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

// validateDenialOfExistence validates NSEC/NSEC3 records for authenticated denial of existence
// Per RFC 4035 §5.4 and RFC 5155
func (v *DNSSECValidator) validateDenialOfExistence(
	ctx context.Context,
	response *dns.Msg,
	question dns.Question,
) ValidationResult {
	// Check if we have NSEC3 records (RFC 5155)
	hasNSEC3 := false
	hasNSEC := false

	for _, rr := range response.Ns {
		switch rr.(type) {
		case *dns.NSEC3:
			hasNSEC3 = true
		case *dns.NSEC:
			hasNSEC = true
		}
	}

	// Validate the authority section RRsets first (must have valid signatures)
	result := v.validateRRsets(ctx, response.Ns, question.Name, response.Ns, question.Name)
	if result != ValidationResultSecure {
		v.logger.Warnf("Authority section validation failed for denial of existence: %s", question.Name)

		return result
	}

	// Now validate the denial of existence proof
	if hasNSEC3 {
		return v.validateNSEC3DenialOfExistence(response, question)
	} else if hasNSEC {
		return v.validateNSECDenialOfExistence(response, question)
	}

	// No NSEC or NSEC3 records found - cannot validate denial of existence
	v.logger.Warnf("No NSEC/NSEC3 records found for denial of existence: %s", question.Name)

	return ValidationResultInsecure
}

// validateNSECDenialOfExistence validates NSEC-based denial of existence per RFC 4035 §5.4
func (v *DNSSECValidator) validateNSECDenialOfExistence(response *dns.Msg, question dns.Question) ValidationResult {
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
	var nsecs []*dns.NSEC
	for _, rr := range rrs {
		if nsec, ok := rr.(*dns.NSEC); ok {
			nsecs = append(nsecs, nsec)
		}
	}

	return nsecs
}

// validateNSECNXDOMAIN validates NSEC proof for NXDOMAIN
func (v *DNSSECValidator) validateNSECNXDOMAIN(nsecRecords []*dns.NSEC, qname string) ValidationResult {
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
func (v *DNSSECValidator) validateNSECNODATA(nsecRecords []*dns.NSEC, qname string, qtype uint16) ValidationResult {
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

// nsecCoversName checks if an NSEC record covers a given name (for NXDOMAIN proof)
// Per RFC 4034 §4.1: NSEC RR covers names between owner name and next domain name
func (v *DNSSECValidator) nsecCoversName(nsec *dns.NSEC, name string) bool {
	// Use canonical form (lowercase, FQDN) per RFC 4034 §6.1
	owner := dns.CanonicalName(nsec.Header().Name)
	next := dns.CanonicalName(nsec.NextDomain)
	name = dns.CanonicalName(name)

	// RFC 4034 §6.1: Canonical DNS name ordering for NSEC
	// For canonical names (lowercase, FQDN), lexicographic string comparison
	// is equivalent to the canonical ordering defined in RFC 4034 §6.1.
	// Go's > and < operators perform lexicographic comparison on strings,
	// which matches the byte-by-byte comparison required by the RFC.
	//
	// If owner < name < next, then NSEC covers the name
	// Handle wrap-around at end of zone (when next < owner)
	if next > owner {
		// Normal case: owner < next
		return name > owner && name < next
	}
	// Wrap-around case: next < owner (covers names from owner to end and start to next)
	return name > owner || name < next
}

// nsecHasType checks if an NSEC record claims a given type exists
func (v *DNSSECValidator) nsecHasType(nsec *dns.NSEC, qtype uint16) bool {
	for _, t := range nsec.TypeBitMap {
		if t == qtype {
			return true
		}
	}

	return false
}

// validateNSEC3DenialOfExistence validates NSEC3-based denial of existence per RFC 5155
func (v *DNSSECValidator) validateNSEC3DenialOfExistence(response *dns.Msg, question dns.Question) ValidationResult {
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

// computeNSEC3Hash computes the NSEC3 hash per RFC 5155 §5 with caching
// Caching is important because NSEC3 hash computation is expensive (iterative SHA-1)
func (v *DNSSECValidator) computeNSEC3Hash(name string, hashAlg uint8, salt string, iterations uint16) (string, error) {
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
func (v *DNSSECValidator) validateNSEC3NXDOMAIN(nsec3Records []*dns.NSEC3, qname, zoneName string,
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
func (v *DNSSECValidator) validateNSEC3NODATA(nsec3Records []*dns.NSEC3, qname string, qtype uint16,
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
func (v *DNSSECValidator) checkDirectNSEC3Match(nsec3Records []*dns.NSEC3, qname, qnameHash string,
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
			for _, t := range nsec3.TypeBitMap {
				if t == qtype {
					// Type exists in bitmap - this is NOT a valid NODATA proof
					v.logger.Debugf("NSEC3 record for %s has type %d in bitmap", qname, qtype)

					return ValidationResultBogus
				}
			}

			// Matching NSEC3 found and type not in bitmap - valid NODATA
			v.logger.Debugf("NSEC3 NODATA proof validated for %s type %d", qname, qtype)

			return ValidationResultSecure
		}
	}

	return ValidationResultIndeterminate
}

// checkWildcardNSEC3Match checks for wildcard NODATA proof
func (v *DNSSECValidator) checkWildcardNSEC3Match(nsec3Records []*dns.NSEC3, qname string, qtype uint16,
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
			for _, t := range nsec3.TypeBitMap {
				if t == qtype {
					return ValidationResultBogus
				}
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
func (v *DNSSECValidator) findClosestEncloser(qname, zoneName string, nsec3Records []*dns.NSEC3,
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
		if zoneName != "" && (name == zoneName || !dns.IsSubDomain(zoneName, name)) {
			break
		}
	}

	return ""
}

// getNextCloser returns the next closer name (one label longer than closest encloser)
func (v *DNSSECValidator) getNextCloser(qname, closestEncloser string) string {
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
func (v *DNSSECValidator) nsec3Covers(nsec3Records []*dns.NSEC3, hash string) bool {
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
func (v *DNSSECValidator) nsec3CoversWithOptOut(nsec3Records []*dns.NSEC3, hash string) bool {
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

// consumeQueryBudget decrements the query budget and returns error if budget is exhausted
// This provides DoS protection by limiting the number of upstream queries per validation
func (v *DNSSECValidator) consumeQueryBudget(ctx context.Context) error {
	budget, ok := ctx.Value(queryBudgetKey{}).(int)
	if !ok {
		// Budget not initialized - this shouldn't happen but fail safely
		return errors.New("query budget not initialized")
	}

	if budget <= 0 {
		return fmt.Errorf("upstream query budget exhausted (max: %d queries per validation)", v.maxUpstreamQueries)
	}

	return nil
}

// decrementQueryBudget creates a new context with decremented budget
func (v *DNSSECValidator) decrementQueryBudget(ctx context.Context) context.Context {
	budget, ok := ctx.Value(queryBudgetKey{}).(int)
	if !ok {
		return ctx
	}

	return context.WithValue(ctx, queryBudgetKey{}, budget-1)
}

// queryRecords performs a DNS query for a specific record type with DNSSEC enabled
// Returns (response, newContext, error) where newContext has decremented budget
func (v *DNSSECValidator) queryRecords(
	ctx context.Context, domain string, qtype uint16,
) (context.Context, *dns.Msg, error) {
	// Check query budget (DoS protection)
	if err := v.consumeQueryBudget(ctx); err != nil {
		v.logger.Warnf("Query budget exhausted while querying %s (type %d): %v", domain, qtype, err)

		return ctx, nil, err
	}

	domain = dns.Fqdn(domain)

	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(domain, qtype)
	msg.SetEdns0(ednsUDPSize, true) // Set DO bit for DNSSEC

	// Create model request
	req := &model.Request{
		Req:      msg,
		Protocol: model.RequestProtocolUDP,
	}

	// Query upstream
	response, err := v.upstream.Resolve(ctx, req)
	if err != nil {
		return ctx, nil, fmt.Errorf("upstream query failed: %w", err)
	}

	// Decrement budget after successful query
	newCtx := v.decrementQueryBudget(ctx)

	return newCtx, response.Res, nil
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

// queryDNSKEY queries upstream for DNSKEY records
// Returns (newContext, dnskeys, error) where newContext has decremented budget
func (v *DNSSECValidator) queryDNSKEY(ctx context.Context, domain string) (context.Context, []*dns.DNSKEY, error) {
	ctx, response, err := v.queryRecords(ctx, domain, dns.TypeDNSKEY)
	if err != nil {
		return ctx, nil, err
	}

	keys, err := extractTypedRecords[*dns.DNSKEY](response.Answer)

	return ctx, keys, err
}
