// Package dnssec implements DNSSEC validation per RFC 4033, 4034, 4035, and 5155.
//
// This package provides cryptographic validation of DNS responses using DNSSEC
// signatures. It validates chains of trust from configured trust anchors down
// to target domains, verifies RRSIGs, and handles authenticated denial of
// existence (NSEC/NSEC3).
//
// Example usage:
//
//	// Create trust anchor store
//	trustAnchors, err := dnssec.NewTrustAnchorStore(nil) // Uses default root anchors
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Create validator
//	validator := dnssec.NewValidator(
//		ctx,
//		trustAnchors,
//		logger,
//		upstream,
//		1,   // cacheExpirationHours
//		10,  // maxChainDepth
//		150, // maxNSEC3Iterations
//		30,  // maxUpstreamQueries
//		3600, // clockSkewToleranceSec
//	)
//
//	// Validate a response
//	result := validator.ValidateResponse(ctx, response, question)
//	switch result {
//	case dnssec.ValidationResultSecure:
//		// Response is cryptographically validated
//	case dnssec.ValidationResultInsecure:
//		// Unsigned zone (no DNSSEC)
//	case dnssec.ValidationResultBogus:
//		// Invalid DNSSEC (should reject)
//	case dnssec.ValidationResultIndeterminate:
//		// Could not complete validation
//	}
package dnssec

//go:generate go tool go-enum -f=$GOFILE --marshal --names --values

import (
	"context"
	"errors"
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

const ednsUDPSize = 4096 // EDNS UDP buffer size for DNSSEC queries

var (
	errUnsupportedRSAExponent = errors.New("unsupported RSA exponent exceeds Go crypto limit")
	errInsecureChain          = errors.New("chain of trust is insecure (no DS records in parent)")
)

// Resolver is the interface for DNS resolution (minimal interface to avoid import cycles)
type Resolver interface {
	Resolve(ctx context.Context, request *model.Request) (*model.Response, error)
}

// ValidationResult represents the result of DNSSEC validation ENUM(
// Secure // Valid DNSSEC signatures and chain of trust
// Insecure // No DNSSEC (unsigned zone)
// Bogus // Invalid DNSSEC (failed validation)
// Indeterminate // Validation could not be completed
// )
type ValidationResult int

// Validator validates DNSSEC signatures and chains of trust
type Validator struct {
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
func (v *Validator) initializeMetrics() {
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

// NewValidator creates a new DNSSEC validator with the given configuration.
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
// Returns a configured Validator ready for use.
func NewValidator(
	ctx context.Context,
	trustAnchors *TrustAnchorStore,
	logger *logrus.Entry,
	upstream Resolver,
	cacheExpirationHours uint,
	maxChainDepth uint,
	maxNSEC3Iterations uint,
	maxUpstreamQueries uint,
	clockSkewToleranceSec uint,
) *Validator {
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

	v := &Validator{
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
func (v *Validator) ValidateResponse(
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
func (v *Validator) hasAnySignatures(response *dns.Msg) bool {
	return len(extractRRSIGs(response.Answer)) > 0 ||
		len(extractRRSIGs(response.Ns)) > 0 ||
		len(extractRRSIGs(response.Extra)) > 0
}

// validateAnswer validates the answer section of a response
func (v *Validator) validateAnswer(
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
func (v *Validator) isNegativeResponse(response *dns.Msg) bool {
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
func (v *Validator) validateNegativeResponse(
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
func (v *Validator) hasAuthorityOrAdditional(response *dns.Msg) bool {
	return len(extractRRSIGs(response.Ns)) > 0 || len(extractRRSIGs(response.Extra)) > 0
}

// validateAuthorityOrAdditional validates authority or additional sections
func (v *Validator) validateAuthorityOrAdditional(
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
func (v *Validator) recordMetrics(start time.Time, result ValidationResult) {
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

// rrsetKey uniquely identifies an RRset by owner name and type
// Per RFC 4035: An RRset is a set of RRs with the same owner name, class, and type
type rrsetKey struct {
	name   string // Owner name (FQDN)
	rrType uint16 // Record type
}

// groupRRsetsByNameAndType groups RRs by their owner name and type (excluding RRSIGs)
// This is critical for DNSSEC validation: each RRset must contain only records
// with the same owner name. For CNAME chains, each CNAME is a separate RRset.
func groupRRsetsByNameAndType(rrs []dns.RR) map[rrsetKey][]dns.RR {
	rrsets := make(map[rrsetKey][]dns.RR)
	for _, rr := range rrs {
		if _, isSig := rr.(*dns.RRSIG); !isSig {
			key := rrsetKey{
				name:   dns.Fqdn(rr.Header().Name),
				rrType: rr.Header().Rrtype,
			}
			rrsets[key] = append(rrsets[key], rr)
		}
	}

	return rrsets
}

// validateRRsets validates all RRsets in a section
func (v *Validator) validateRRsets(
	ctx context.Context, rrs []dns.RR, domain string, nsRecords []dns.RR, qname string,
) ValidationResult {
	// Extract all RRSIGs
	sigs := extractRRSIGs(rrs)
	if len(sigs) == 0 {
		v.logger.Debugf("No RRSIGs found in section for %s", domain)

		return ValidationResultInsecure
	}

	// Group RRs by owner name and type
	// Per RFC 4035: Each RRset must have the same owner name, class, and type
	rrsets := groupRRsetsByNameAndType(rrs)

	// Track mixed security statuses (can occur in CNAME chains crossing zone boundaries)
	hasSecure := false
	hasInsecure := false

	// Validate each RRset
	for key, rrset := range rrsets {
		// Use the actual RRset owner name instead of the generic domain parameter
		result := v.validateSingleRRset(ctx, key.rrType, rrset, sigs, key.name, nsRecords, qname)

		switch result {
		case ValidationResultBogus:
			// Bogus always fails validation
			return ValidationResultBogus
		case ValidationResultIndeterminate:
			// Indeterminate always fails validation
			return ValidationResultIndeterminate
		case ValidationResultSecure:
			hasSecure = true
		case ValidationResultInsecure:
			hasInsecure = true
		}
	}

	// Per RFC 4035 §5.2: A mix of Secure and Insecure RRsets is acceptable
	// This happens with CNAME chains crossing from unsigned to signed zones (or vice versa)
	if hasSecure {
		// At least one RRset is validated with DNSSEC signatures
		return ValidationResultSecure
	}

	if hasInsecure {
		// All RRsets are from unsigned (insecure) zones - no DNSSEC validation possible
		return ValidationResultInsecure
	}

	// Shouldn't reach here, but return Secure as fallback
	return ValidationResultSecure
}

// validateSingleRRset validates a single RRset with its signatures
func (v *Validator) validateSingleRRset(
	ctx context.Context, rrType uint16, rrset []dns.RR, sigs []*dns.RRSIG,
	domain string, nsRecords []dns.RR, qname string,
) ValidationResult {
	// Find matching RRSIGs for this RRset
	// Per RFC 6840 §5.11, we should prefer stronger algorithms to prevent downgrade attacks
	// RRSIGs must match both the type covered AND the owner name
	matchingRRSIGs := findMatchingRRSIGs(sigs, dns.Fqdn(domain), rrType)

	if len(matchingRRSIGs) == 0 {
		// RFC 4035 §5.2: Before treating missing RRSIG as Bogus, check if the zone is insecure (unsigned)
		// This handles cases where CNAME chains cross zone boundaries with different security statuses
		rrsetName := dns.Fqdn(rrset[0].Header().Name)

		return v.handleMissingRRSIG(ctx, rrType, rrsetName)
	}

	// RFC 4035 §5.3.1: Try all RRSIGs in order of preference (strongest algorithm first)
	// Per RFC 4035 §2.2: If ANY signature verifies successfully, the RRset is Secure
	// Only if ALL signatures fail should we return Bogus or Insecure
	sortedSigs := v.sortRRSIGsByStrength(matchingRRSIGs)

	var (
		lastErr                 error
		hasUnsupportedSignature bool
		hasOtherFailure         bool
		hasInsecureChain        bool
	)

	for _, matchingSig := range sortedSigs {
		success, err := v.tryVerifyWithRRSIG(ctx, rrset, matchingSig, domain, nsRecords, qname, rrType)
		if success {
			// Check if signature verified but chain is insecure
			if errors.Is(err, errInsecureChain) {
				// Signature verified cryptographically, but no chain of trust to root
				// Per RFC 5155 §6: Zone is signed but delegation is insecure (NSEC3 Opt-Out)
				hasInsecureChain = true

				continue
			}

			// At least one signature verified successfully with full chain of trust
			return ValidationResultSecure
		}

		if err != nil {
			if errors.Is(err, errUnsupportedRSAExponent) {
				// Track unsupported signatures but continue trying others
				hasUnsupportedSignature = true
			} else {
				// Track other failures
				hasOtherFailure = true
				lastErr = err
			}
		}
	}

	// Determine final result based on failure types
	return v.determineFinalValidationResult(
		domain, len(sortedSigs), hasInsecureChain, hasUnsupportedSignature, hasOtherFailure, lastErr,
	)
}

// determineFinalValidationResult determines the validation result when all RRSIGs have been tried
func (v *Validator) determineFinalValidationResult(
	domain string, sigCount int, hasInsecureChain, hasUnsupportedSignature, hasOtherFailure bool, lastErr error,
) ValidationResult {
	// Check if any signature verified with insecure chain
	// This takes precedence over other failure types
	if hasInsecureChain {
		v.logger.Debugf("RRSIG verified for %s but chain of trust is insecure (no DS in parent) - treating as Insecure",
			domain)

		return ValidationResultInsecure
	}

	// All RRSIGs failed - determine result based on failure types
	// Per RFC 4035 §2.2: Treat unsupported algorithms as Insecure only if NO other errors occurred
	if hasUnsupportedSignature && !hasOtherFailure {
		v.logger.Warnf(
			"All RRSIG signatures for %s use unsupported algorithms - treating as Insecure per RFC 4035 §2.2",
			domain)

		return ValidationResultInsecure
	}

	// At least one signature failed validation (not just unsupported) - this is Bogus
	v.logger.Warnf("All RRSIG verification attempts failed for %s (tried %d signatures), last error: %v",
		domain, sigCount, lastErr)

	return ValidationResultBogus
}

// tryVerifyWithRRSIG attempts to verify an RRset with a single RRSIG
// Returns true if verification succeeded, false otherwise
func (v *Validator) tryVerifyWithRRSIG(
	ctx context.Context, rrset []dns.RR, matchingSig *dns.RRSIG, domain string,
	nsRecords []dns.RR, qname string, rrType uint16,
) (bool, error) {
	// Validate signer name
	signerName := matchingSig.SignerName
	rrsetName := dns.Fqdn(rrset[0].Header().Name)

	// RFC 4035 §2.2: For DNSKEY RRsets, the signer must equal the owner (self-signed at zone apex)
	if rrType == dns.TypeDNSKEY {
		if signerName != rrsetName {
			v.logger.Debugf("Skipping RRSIG: DNSKEY signer %s must equal owner %s (RFC 4035 §2.2)", signerName, rrsetName)

			return false, nil
		}
	} else {
		// For non-DNSKEY RRsets, signer must be a parent of the RRset owner
		if !validateSignerName(signerName, rrsetName) {
			v.logger.Debugf("Skipping RRSIG: signer name %s is not a parent of RRset owner %s", signerName, rrsetName)

			return false, nil
		}
	}

	// Query and match DNSKEY
	_, matchingKey, err := v.queryAndMatchDNSKEY(ctx, signerName, matchingSig.KeyTag, matchingSig.Algorithm)
	if err != nil {
		v.logger.Debugf("Skipping RRSIG (algorithm=%d, keytag=%d): DNSKEY query/match failed: %v",
			matchingSig.Algorithm, matchingSig.KeyTag, err)

		return false, err
	}

	// Check for unsupported RSA exponents (Go crypto limitation)
	if hasUnsupportedRSAExponent(matchingKey) {
		v.logger.Debugf(
			"DNSKEY for %s (algorithm=%d, keytag=%d) has unsupported RSA exponent "+
				"(exceeds 2^31-1, Go crypto limitation) - treating zone as Insecure per RFC 4035 §2.2",
			domain, matchingSig.Algorithm, matchingSig.KeyTag)

		return false, errUnsupportedRSAExponent
	}

	// Validate the DNSKEY via chain of trust
	chainResult := v.walkChainOfTrust(ctx, signerName)

	// Only skip verification if chain validation failed with Bogus or Indeterminate
	// Per RFC 5155 §6: NSEC3 Opt-Out allows unsigned delegations, but if the zone IS signed
	// (has RRSIG records), we should still validate those signatures cryptographically
	if chainResult == ValidationResultBogus || chainResult == ValidationResultIndeterminate {
		v.logger.Debugf("Skipping RRSIG (algorithm=%d, keytag=%d): chain of trust validation failed: %s",
			matchingSig.Algorithm, matchingSig.KeyTag, chainResult.String())

		return false, nil
	}

	// Verify the signature and return result based on chain status
	return v.verifyAndReturnResult(rrset, matchingSig, matchingKey, nsRecords, qname, domain, chainResult)
}

// verifyAndReturnResult verifies the signature and returns the result based on chain status
func (v *Validator) verifyAndReturnResult(
	rrset []dns.RR, matchingSig *dns.RRSIG, matchingKey *dns.DNSKEY,
	nsRecords []dns.RR, qname, domain string, chainResult ValidationResult,
) (bool, error) {
	// Verify the signature cryptographically (even if chain is Insecure)
	if err := v.verifyRRSIG(rrset, matchingSig, matchingKey, nsRecords, qname); err != nil {
		v.logger.Debugf("RRSIG verification failed for algorithm=%d, keytag=%d: %v (trying next RRSIG if available)",
			matchingSig.Algorithm, matchingSig.KeyTag, err)

		return false, err
	}

	// Signature verified successfully
	if chainResult == ValidationResultInsecure {
		// Signature is cryptographically valid, but chain of trust to root cannot be established
		// This happens with NSEC3 Opt-Out when parent has no DS but child is signed
		v.logger.Debugf("RRSIG verified for %s (algorithm=%d, keytag=%d), but chain is Insecure",
			domain, matchingSig.Algorithm, matchingSig.KeyTag)

		return true, errInsecureChain
	}

	// Verification succeeded with full chain of trust!
	v.logger.Debugf("Successfully verified RRset for %s with algorithm=%d, keytag=%d",
		domain, matchingSig.Algorithm, matchingSig.KeyTag)

	return true, nil
}

// handleMissingRRSIG determines the validation result when no RRSIG is found for an RRset
// Per RFC 4035 §5.2, we must check if the zone is unsigned before treating it as Bogus
func (v *Validator) handleMissingRRSIG(ctx context.Context, rrType uint16, rrsetName string) ValidationResult {
	// Check if this zone is unsigned by checking for DS records
	zoneSecurityStatus := v.checkZoneSecurityStatus(ctx, rrsetName)

	if zoneSecurityStatus == ValidationResultInsecure {
		// Zone is unsigned/insecure - unsigned RRsets are acceptable per RFC 4035 §5.2
		v.logger.Debugf("RRset type %d in %s has no RRSIG, but zone is insecure - acceptable", rrType, rrsetName)

		return ValidationResultInsecure
	}

	if zoneSecurityStatus == ValidationResultIndeterminate {
		// Cannot determine zone security status - treat conservatively as Indeterminate
		v.logger.Warnf("Cannot determine security status for zone of %s - treating as indeterminate", rrsetName)

		return ValidationResultIndeterminate
	}

	// Zone is secure (has DS records) but RRSIG missing - this is Bogus
	v.logger.Warnf("No RRSIG found for RRset type %d in %s (zone is secure)", rrType, rrsetName)

	return ValidationResultBogus
}

// checkZoneSecurityStatus determines if a zone is signed (Secure) or unsigned (Insecure)
// by checking for DS records in the parent zone.
// Per RFC 4035 §5.2: A zone is insecure if there's an authenticated NSEC/NSEC3 proving no DS exists.
// A zone is secure if DS records exist.
// Returns: Secure, Insecure, or Indeterminate
func (v *Validator) checkZoneSecurityStatus(ctx context.Context, domain string) ValidationResult {
	domain = dns.Fqdn(domain)

	// Check cache first - we may have already validated this zone
	if cached, found := v.getCachedValidation(domain); found {
		v.logger.Debugf("Using cached security status for %s: %s", domain, cached.String())

		return cached
	}

	// Get parent domain to query for DS records
	parentDomain := v.getParentDomain(domain)
	if parentDomain == "" {
		// Root or TLD with no parent - treat as insecure for this check
		// (actual validation would go through trust anchors)
		v.logger.Debugf("Domain %s has no parent for DS lookup", domain)

		return ValidationResultInsecure
	}

	// Query DS records for this domain from the parent zone
	ctx, dsResponse, err := v.queryRecords(ctx, domain, dns.TypeDS)
	if err != nil {
		v.logger.Debugf("DS query failed for %s: %v", domain, err)

		return ValidationResultIndeterminate
	}

	// Check if DS records exist
	dsRecords, extractErr := extractTypedRecords[*dns.DS](dsResponse.Answer, dsResponse.Ns)
	if extractErr != nil {
		// No DS records - handle based on proof of absence
		return v.handleNoDSRecords(ctx, domain, parentDomain, dsResponse)
	}

	// DS records exist - zone is signed (secure)
	v.logger.Debugf("Zone %s is secure (DS records exist: %d)", domain, len(dsRecords))
	// Don't cache as Secure here - full validation might fail
	// Just return Secure to indicate the zone should have signatures

	return ValidationResultSecure
}

// handleNoDSRecords determines zone security status when no DS records are found
func (v *Validator) handleNoDSRecords(
	ctx context.Context, domain, parentDomain string, dsResponse *dns.Msg,
) ValidationResult {
	// Check for NSEC/NSEC3 proof of absence
	hasNSEC := len(extractNSECRecords(dsResponse.Ns)) > 0
	hasNSEC3 := len(extractNSEC3Records(dsResponse.Ns)) > 0

	if hasNSEC || hasNSEC3 {
		// Authenticated denial of DS existence - zone is insecure (unsigned)
		v.logger.Debugf("Zone %s is insecure (no DS, with NSEC/NSEC3 proof)", domain)
		result := ValidationResultInsecure
		v.setCachedValidation(domain, result)

		return result
	}

	// No DS and no proof - this might be a non-delegation (e.g., subdomain in parent zone)
	// Try walking up to parent zone
	v.logger.Debugf("No DS or proof for %s, checking parent zone", domain)

	if parentDomain != "" {
		parentResult := v.checkZoneSecurityStatus(ctx, parentDomain)
		if parentResult == ValidationResultInsecure {
			// Parent zone is unsigned, so this name is also unsigned
			v.logger.Debugf("Parent zone %s is insecure, so %s is also insecure", parentDomain, domain)
			result := ValidationResultInsecure
			v.setCachedValidation(domain, result)

			return result
		}
		if parentResult == ValidationResultSecure {
			// Parent is signed, so this non-delegation should have been signed too
			v.logger.Debugf("Parent zone %s is secure but %s has no DS - treating as indeterminate", parentDomain, domain)
			result := ValidationResultIndeterminate
			v.setCachedValidation(domain, result)

			return result
		}
	}

	// No DS and no proof - indeterminate
	v.logger.Debugf("Zone %s security status indeterminate (no DS, no proof)", domain)
	result := ValidationResultIndeterminate
	v.setCachedValidation(domain, result)

	return result
}
