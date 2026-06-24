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
//	// Initialize:
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
	"log/slog"
	"sync"
	"time"

	"github.com/0xERR0R/blocky/cache"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	expirationcache "github.com/0xERR0R/expiration-cache"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
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
	logger                *slog.Logger
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
	logger *slog.Logger,
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
			Shards:          cache.ShardCount(),
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
	v.logger.DebugContext(ctx, "DNSSEC validation requested", slog.String("domain", question.Name))

	// Initialize query budget for this validation request (DoS protection)
	ctx = context.WithValue(ctx, queryBudgetKey{}, int(v.maxUpstreamQueries))

	var result ValidationResult

	// Dispatch to appropriate validator based on response type
	switch {
	case !v.hasAnySignatures(response):
		// A response with no RRSIGs does NOT automatically mean the zone is unsigned.
		// Determine the zone's security status first: if the zone is signed (chains to
		// a trust anchor) then a missing-signature answer is forged, not insecure.
		result = v.classifyUnsignedResponse(ctx, question)
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

// classifyUnsignedResponse determines the validation result for a response that
// carries no RRSIG records. Per RFC 4035 §5.2 the absence of signatures only means
// "insecure" if the queried name is provably below an insecure delegation. If the
// enclosing zone is secure (chains to a trust anchor) with no authenticated proof of
// an insecure delegation, an unsigned answer is bogus, not insecure.
func (v *Validator) classifyUnsignedResponse(ctx context.Context, question dns.Question) ValidationResult {
	status := v.checkZoneSecurityStatus(ctx, question.Name)
	if status == ValidationResultSecure {
		v.logger.WarnContext(ctx, "no RRSIG but zone is secure, treating as bogus", slog.String("domain", question.Name))

		return ValidationResultBogus
	}

	// Insecure (genuinely unsigned zone) or Indeterminate (cannot determine).
	v.logger.DebugContext(ctx, "no RRSIG",
		slog.String("domain", question.Name), slog.String("zone_status", status.String()))

	return status
}

// validateAnswer validates the answer section of a response
func (v *Validator) validateAnswer(
	ctx context.Context, response *dns.Msg, question dns.Question,
) ValidationResult {
	result := v.validateRRsets(ctx, response.Answer, question.Name, response.Ns, question.Name)
	if result != ValidationResultSecure {
		v.logger.WarnContext(ctx, "answer validation failed",
			slog.String("domain", question.Name), slog.String("result", result.String()))
	} else {
		v.logger.DebugContext(ctx, "DNSSEC validation succeeded", slog.String("domain", question.Name))
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
		v.logger.DebugContext(ctx, "no signatures in authority section for denial of existence",
			slog.String("domain", question.Name))

		return ValidationResultInsecure
	}

	result := v.validateDenialOfExistence(ctx, response, question)
	if result != ValidationResultSecure {
		v.logger.WarnContext(ctx, "denial of existence validation failed",
			slog.String("domain", question.Name), slog.String("result", result.String()))
	} else {
		v.logger.DebugContext(ctx, "denial of existence validated", slog.String("domain", question.Name))
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
		v.logger.WarnContext(ctx, "authority/additional validation failed",
			slog.String("domain", question.Name), slog.String("result", result.String()))
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
	return util.ExtractRecordsFromSlice[*dns.RRSIG](rrs)
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
		v.logger.DebugContext(ctx, "no RRSIGs found in section", slog.String("domain", domain))

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
		v.logger.Debug("RRSIG verified but chain is insecure, treating as Insecure", slog.String("domain", domain))

		return ValidationResultInsecure
	}

	// All RRSIGs failed - determine result based on failure types
	// Per RFC 4035 §2.2: Treat unsupported algorithms as Insecure only if NO other errors occurred
	if hasUnsupportedSignature && !hasOtherFailure {
		v.logger.Warn("all RRSIG signatures use unsupported algorithms, treating as Insecure", slog.String("domain", domain))

		return ValidationResultInsecure
	}

	// At least one signature failed validation (not just unsupported) - this is Bogus
	v.logger.Warn("all RRSIG verification attempts failed",
		slog.String("domain", domain), slog.Int("sig_count", sigCount), log.AttrError(lastErr))

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
			v.logger.DebugContext(ctx, "skipping RRSIG: DNSKEY signer must equal owner (RFC 4035 §2.2)",
				slog.String("signer", signerName), slog.String("owner", rrsetName))

			return false, nil
		}
	} else {
		// For non-DNSKEY RRsets, signer must be a parent of the RRset owner
		if !validateSignerName(signerName, rrsetName) {
			v.logger.DebugContext(ctx, "skipping RRSIG: signer is not parent of owner",
				slog.String("signer", signerName), slog.String("owner", rrsetName))

			return false, nil
		}
	}

	// Query and match DNSKEY
	_, matchingKey, err := v.queryAndMatchDNSKEY(ctx, signerName, matchingSig.KeyTag, matchingSig.Algorithm)
	if err != nil {
		v.logger.DebugContext(ctx, "skipping RRSIG: DNSKEY query/match failed",
			slog.Int("algorithm", int(matchingSig.Algorithm)), slog.Int("keytag", int(matchingSig.KeyTag)), log.AttrError(err))

		return false, err
	}

	// Check for unsupported RSA exponents (Go crypto limitation)
	if hasUnsupportedRSAExponent(matchingKey) {
		v.logger.DebugContext(ctx, "DNSKEY has unsupported RSA exponent, treating zone as Insecure",
			slog.String("domain", domain), slog.Int("algorithm", int(matchingSig.Algorithm)),
			slog.Int("keytag", int(matchingSig.KeyTag)))

		return false, errUnsupportedRSAExponent
	}

	// Validate the DNSKEY via chain of trust
	chainResult := v.walkChainOfTrust(ctx, signerName)

	// Only skip verification if chain validation failed with Bogus or Indeterminate
	// Per RFC 5155 §6: NSEC3 Opt-Out allows unsigned delegations, but if the zone IS signed
	// (has RRSIG records), we should still validate those signatures cryptographically
	if chainResult == ValidationResultBogus || chainResult == ValidationResultIndeterminate {
		v.logger.DebugContext(ctx, "skipping RRSIG: chain of trust validation failed",
			slog.Int("algorithm", int(matchingSig.Algorithm)), slog.Int("keytag", int(matchingSig.KeyTag)),
			slog.String("chain_result", chainResult.String()))

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
		v.logger.Debug("RRSIG verification failed",
			slog.Int("algorithm", int(matchingSig.Algorithm)), slog.Int("keytag", int(matchingSig.KeyTag)), log.AttrError(err))

		return false, err
	}

	// Signature verified successfully
	if chainResult == ValidationResultInsecure {
		// Signature is cryptographically valid, but chain of trust to root cannot be established
		// This happens with NSEC3 Opt-Out when parent has no DS but child is signed
		v.logger.Debug("RRSIG verified but chain is Insecure",
			slog.String("domain", domain), slog.Int("algorithm", int(matchingSig.Algorithm)),
			slog.Int("keytag", int(matchingSig.KeyTag)))

		return true, errInsecureChain
	}

	// Verification succeeded with full chain of trust!
	v.logger.Debug("successfully verified RRset",
		slog.String("domain", domain), slog.Int("algorithm", int(matchingSig.Algorithm)),
		slog.Int("keytag", int(matchingSig.KeyTag)))

	return true, nil
}

// handleMissingRRSIG determines the validation result when no RRSIG is found for an RRset
// Per RFC 4035 §5.2, we must check if the zone is unsigned before treating it as Bogus
func (v *Validator) handleMissingRRSIG(ctx context.Context, rrType uint16, rrsetName string) ValidationResult {
	// Check if this zone is unsigned by checking for DS records
	zoneSecurityStatus := v.checkZoneSecurityStatus(ctx, rrsetName)

	if zoneSecurityStatus == ValidationResultInsecure {
		// Zone is unsigned/insecure - unsigned RRsets are acceptable per RFC 4035 §5.2
		v.logger.DebugContext(ctx, "RRset has no RRSIG but zone is insecure",
			slog.Int("type", int(rrType)), slog.String("domain", rrsetName))

		return ValidationResultInsecure
	}

	if zoneSecurityStatus == ValidationResultIndeterminate {
		// Cannot determine zone security status - treat conservatively as Indeterminate
		v.logger.WarnContext(ctx, "cannot determine zone security status", slog.String("domain", rrsetName))

		return ValidationResultIndeterminate
	}

	// Zone is secure (has DS records) but RRSIG missing - this is Bogus
	v.logger.WarnContext(ctx, "no RRSIG found for RRset in secure zone",
		slog.Int("type", int(rrType)), slog.String("domain", rrsetName))

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
	if cached, found := v.getCachedValidation(ctx, domain); found {
		v.logger.DebugContext(ctx, "using cached security status",
			slog.String("domain", domain), slog.String("status", cached.String()))

		return cached
	}

	// A configured trust anchor is an operator-asserted secure entry point: by
	// definition the zone is signed. This covers both the IANA root anchor and any
	// custom anchor, and is what lets us reject unsigned answers for a signed zone.
	if v.trustAnchors.HasTrustAnchor(domain) {
		v.logger.DebugContext(ctx, "domain has a configured trust anchor", slog.String("domain", domain))

		return ValidationResultSecure
	}

	// Get parent domain to query for DS records
	parentDomain := v.getParentDomain(domain)
	if parentDomain == "" {
		// Reached the root without a configured trust anchor: security status cannot be
		// established from the chain.
		v.logger.DebugContext(ctx, "domain has no parent and no trust anchor", slog.String("domain", domain))

		return v.classifyUndetermined(domain)
	}

	// Query DS records for this domain from the parent zone
	ctx, dsResponse, err := v.queryRecords(ctx, domain, dns.TypeDS)
	if err != nil {
		// Could not reach the upstream (e.g. answering from cache after the upstream is
		// gone). Fail closed if the name lives under a trust anchor; we must not serve an
		// unsigned answer for a secured hierarchy just because we cannot reach a resolver.
		v.logger.DebugContext(ctx, "DS query failed", slog.String("domain", domain), log.AttrError(err))

		return v.classifyUndetermined(domain)
	}

	// Check if DS records exist
	dsRecords, extractErr := extractTypedRecords[*dns.DS](dsResponse.Answer, dsResponse.Ns)
	if extractErr != nil {
		// No DS records - handle based on proof of absence
		return v.handleNoDSRecords(ctx, domain, parentDomain, dsResponse)
	}

	// DS records are present, but their mere presence is not proof the zone is signed: an
	// injected/forged DS could otherwise force an unsigned name to be classified secure and
	// thus SERVFAIL its (legitimately unsigned) answers. Require the DS RRset to be signed
	// by the parent zone before trusting it.
	dsRRSIG := v.findDSRRSIG(dsResponse, domain)
	if dsRRSIG == nil {
		v.logger.WarnContext(ctx, "DS records present but unsigned", slog.String("domain", domain))

		return v.classifyUndetermined(domain)
	}

	res := v.validateDSRecordSignature(ctx, domain, parentDomain, convertDSToRRset(dsRecords), dsRRSIG)
	if res != ValidationResultSecure {
		v.logger.WarnContext(ctx, "DS RRSIG failed validation",
			slog.String("domain", domain), slog.String("result", res.String()))

		return v.classifyUndetermined(domain)
	}

	// DS records exist and validate - zone is signed (secure).
	v.logger.DebugContext(ctx, "zone is secure", slog.String("domain", domain), slog.Int("ds_records", len(dsRecords)))
	// Don't cache as Secure here - full validation of the answer might still fail.

	return ValidationResultSecure
}

// isUnderTrustAnchor reports whether domain, or any of its ancestors, has a trust anchor -
// including the implicit IANA root anchor installed by default. Because a validating
// resolver must hold a secure entry point to validate at all, any name below a trust anchor
// is presumed secure until an AUTHENTICATED proof of an insecure delegation (a signed
// NSEC/NSEC3 DS denial) says otherwise. Under the default configuration the root anchor is
// present, so this is true for the whole namespace - which is exactly what closes the
// unsigned-answer bypass (GHSA-x845-2f78-7v36 finding 1): a forged unsigned answer can no
// longer pass merely because the attacker also strips the DS/DNSKEY chain.
func (v *Validator) isUnderTrustAnchor(domain string) bool {
	for d := dns.Fqdn(domain); d != ""; d = v.getParentDomain(d) {
		if v.trustAnchors.HasTrustAnchor(d) {
			return true
		}
	}

	return false
}

// classifyUndetermined decides the security status when the chain status cannot be
// established (no authenticated DS proof). It fails closed - Secure, so an unsigned answer
// becomes bogus - for any name under a trust anchor (including the default root anchor),
// because a name below a secure entry point must be proven insecure by an AUTHENTICATED
// denial of existence before its unsigned answer may be trusted. Only names with no trust
// anchor anywhere in their hierarchy stay Indeterminate (the answer passes through). This is
// NOT cached: it is not derived from an authenticated proof, so a later reachable upstream
// can still establish the real status.
func (v *Validator) classifyUndetermined(domain string) ValidationResult {
	if v.isUnderTrustAnchor(domain) {
		v.logger.Debug("zone status undetermined but under trust anchor, treating as secure", slog.String("domain", domain))

		return ValidationResultSecure
	}

	v.logger.Debug("zone status indeterminate, no trust anchor in hierarchy", slog.String("domain", domain))

	return ValidationResultIndeterminate
}

// handleNoDSRecords determines zone security status when no DS records are found.
// A DS NODATA response can only downgrade a zone to insecure if it carries an
// AUTHENTICATED denial of the DS type (a signed NSEC/NSEC3 that chains to a trust
// anchor); the mere presence of NSEC/NSEC3 records is not proof.
func (v *Validator) handleNoDSRecords(
	ctx context.Context, domain, parentDomain string, dsResponse *dns.Msg,
) ValidationResult {
	hasNSEC := len(extractNSECRecords(dsResponse.Ns)) > 0
	hasNSEC3 := len(extractNSEC3Records(dsResponse.Ns)) > 0

	if hasNSEC || hasNSEC3 {
		if v.isAuthenticatedDSDenial(ctx, domain, dsResponse) {
			// Authenticated proof that no DS exists: genuine insecure delegation.
			v.logger.DebugContext(ctx, "zone is insecure (authenticated DS denial)", slog.String("domain", domain))
			result := ValidationResultInsecure
			v.setCachedValidation(ctx, domain, result)

			return result
		}

		// Unauthenticated/forged denial - must NOT be trusted, and must NOT be cached.
		// Fall through and determine status from the parent zone instead.
		v.logger.WarnContext(ctx, "unauthenticated NSEC/NSEC3 in DS response, ignoring", slog.String("domain", domain))
	}

	// No DS and no authenticated proof of absence. Determine status from the parent.
	v.logger.DebugContext(ctx, "no authenticated DS-absence proof, checking parent zone", slog.String("domain", domain))

	if parentDomain != "" {
		parentStatus := v.checkZoneSecurityStatus(ctx, parentDomain)
		if parentStatus == ValidationResultInsecure {
			// Below an insecure delegation - this name is also unsigned.
			v.logger.DebugContext(ctx, "parent zone is insecure, domain also insecure",
				slog.String("parent", parentDomain), slog.String("domain", domain))
			result := ValidationResultInsecure
			v.setCachedValidation(ctx, domain, result)

			return result
		}
		if parentStatus == ValidationResultSecure {
			// Parent is secure but there is no authenticated proof that this name is an
			// insecure delegation. We cannot positively conclude from the parent alone that
			// the name itself is signed (the proof may have been stripped, or this may be a
			// forged unsigned answer), so defer to the trust-anchor-aware default: fail
			// closed only when the operator explicitly anchored this hierarchy, otherwise
			// stay indeterminate. Do NOT cache - not derived from an authenticated proof.
			v.logger.DebugContext(ctx, "parent zone secure but no authenticated DS denial",
				slog.String("parent", parentDomain), slog.String("domain", domain))

			return v.classifyUndetermined(domain)
		}
	}

	// No authenticated proof and no usable parent result - fall back to the
	// trust-anchor-aware default (fail closed under a trust anchor).
	return v.classifyUndetermined(domain)
}

// isAuthenticatedDSDenial reports whether dsResponse carries an authenticated proof
// (a signed NSEC/NSEC3 chaining to a trust anchor) that the DS type is absent for
// domain - i.e. a genuine insecure delegation. Mere presence of NSEC/NSEC3 is not
// sufficient; the records must be cryptographically validated.
func (v *Validator) isAuthenticatedDSDenial(ctx context.Context, domain string, dsResponse *dns.Msg) bool {
	// First require the authority section (the NSEC/NSEC3 records and their RRSIGs) to
	// cryptographically validate and chain to a trust anchor. An unsigned or forged denial
	// proves nothing and must never downgrade a zone to insecure.
	if v.validateRRsets(ctx, dsResponse.Ns, domain, dsResponse.Ns, domain) != ValidationResultSecure {
		return false
	}

	// With an authenticated authority section, both an explicit NSEC/NSEC3 NODATA proof
	// (Secure) and an NSEC3 Opt-Out span covering the name (Insecure) are authenticated
	// proofs that no DS exists - i.e. a genuine insecure (unsigned) delegation. Opt-Out is
	// the standard mechanism by which signed TLDs (.com/.net/.org, ...) delegate to their
	// unsigned children, so rejecting the Insecure result would wrongly treat the bulk of
	// the unsigned Internet as bogus.
	hasNSEC := len(extractNSECRecords(dsResponse.Ns)) > 0
	proof := v.validateDSAbsenceProof(domain, dsResponse, hasNSEC)

	return proof == ValidationResultSecure || proof == ValidationResultInsecure
}
