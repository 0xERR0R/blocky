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
func (v *Validator) validateRRsets(
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

	// Track mixed security statuses (can occur in CNAME chains crossing zone boundaries)
	hasSecure := false
	hasInsecure := false

	// Validate each RRset
	for rrType, rrset := range rrsets {
		result := v.validateSingleRRset(ctx, rrType, rrset, sigs, domain, nsRecords, qname)

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
	matchingRRSIGs := findMatchingRRSIGsForType(sigs, rrType)

	if len(matchingRRSIGs) == 0 {
		// RFC 4035 §5.2: Before treating missing RRSIG as Bogus, check if the zone is insecure (unsigned)
		// This handles cases where CNAME chains cross zone boundaries with different security statuses
		// e.g., CNAME in unsigned zone pointing to A records in signed zone
		rrsetName := dns.Fqdn(rrset[0].Header().Name)

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
