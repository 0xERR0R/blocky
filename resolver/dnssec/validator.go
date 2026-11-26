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
//	verdict := validator.Validate(ctx, response, question)
//	switch verdict.Result {
//	case dnssec.ValidationResultSecure:
//		// Response is cryptographically validated
//	case dnssec.ValidationResultInsecure:
//		// Unsigned zone (no DNSSEC)
//	case dnssec.ValidationResultBogus:
//		// Invalid DNSSEC, or validation that could not be completed (should reject, and
//		// verdict.EDE and verdict.Text say why)
//	case dnssec.ValidationResultIndeterminate:
//		// No trust anchor above the name
//	}
package dnssec

//go:generate go tool go-enum -f=$GOFILE --marshal --names --values

import (
	"context"
	"errors"
	"fmt"
	"slices"
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

// errDNSKEYUnavailable marks a lookup of a zone's DNSKEY RRset that could not be completed (see
// lookup). This is "could not validate", not proof of an invalid signature, so the zone gets no
// status that is kept. Distinct from a DNSKEY RRset that arrives and does not verify, which is a
// genuine failure.
var errDNSKEYUnavailable = errors.New("DNSKEY could not be retrieved (unreachable)")

// extendedError is why a validation failed, with what a client is told of it: the INFO-CODE and
// the EXTRA-TEXT of an extended DNS error (RFC 8914 §2). cause, if there is one, is for the log.
type extendedError struct {
	code  uint16
	text  string
	cause error
}

func (e *extendedError) Error() string {
	if e.cause == nil {
		return e.text
	}

	return e.text + ": " + e.cause.Error()
}

func (e *extendedError) Unwrap() error {
	return e.cause
}

// extended returns the extendedError with code and the text that format and args give
func extended(code uint16, format string, args ...any) *extendedError {
	return &extendedError{code: code, text: fmt.Sprintf(format, args...)}
}

// bogus is extended for a failure that only "DNSSEC Bogus" names (RFC 8914 §4.7)
func bogus(format string, args ...any) *extendedError {
	return extended(dns.ExtendedErrorCodeDNSBogus, format, args...)
}

// unsupported is extended for an RRSIG of an algorithm, or of a key, that nothing here verifies
// with (RFC 8914 §4.2)
func unsupported(format string, args ...any) *extendedError {
	return extended(dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm, format, args...)
}

// Resolver is the interface for DNS resolution (minimal interface to avoid import cycles)
type Resolver interface {
	Resolve(ctx context.Context, request *model.Request) (*model.Response, error)
}

// ValidationResult represents the result of DNSSEC validation. The results are ordered from worst
// to best, so a result that was never set is Bogus. ENUM(
// Bogus // Invalid DNSSEC (failed validation, or validation that could not be completed)
// Indeterminate // No trust anchor above the name
// Insecure // No DNSSEC (unsigned zone)
// Secure // Valid DNSSEC signatures and chain of trust
// )
type ValidationResult int

// worst returns the lowest of the given results
func worst(result ValidationResult, others ...ValidationResult) ValidationResult {
	for _, other := range others {
		result = min(result, other)
	}

	return result
}

// Validator validates DNSSEC signatures and chains of trust
type Validator struct {
	trustAnchors          *TrustAnchorStore
	logger                *logrus.Entry
	upstream              Resolver // Used to query for DNSKEY and DS records
	validationCache       cache.ExpiringCache[zoneStatus]
	cacheExpiration       time.Duration
	maxChainDepth         uint // Maximum number of zones in a chain of trust below its trust anchor
	maxNSEC3Iterations    uint // Maximum NSEC3 iterations (RFC 5155 §10.3)
	maxUpstreamQueries    uint // Maximum upstream queries for the validations of one client query (DoS protection)
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
//   - maxChainDepth: Maximum number of zones in a chain of trust below its trust anchor (0
//     defaults to 10, prevents DoS)
//   - maxNSEC3Iterations: Maximum NSEC3 iterations (0 defaults to 150, prevents DoS)
//   - maxUpstreamQueries: Maximum upstream queries for the validations of one client query (0
//     defaults to 30, prevents DoS)
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
		validationCache: expirationcache.NewCache[zoneStatus](ctx, expirationcache.Options{
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

// Verdict is what validation says of a reply: its status and, for a Bogus reply, why, as the
// extended DNS error that tells a client so (RFC 8914 §2). EDE and Text mean something only if
// Result is Bogus: the zero value of EDE is a code too. For a Secure reply it says how long each
// RRset of the reply is authentic.
//
// RanOut says that the validation of a Bogus reply asked for more than it had of one of its
// budgets: signature verifications, NSEC3 hashes or upstream queries (see budget). The same
// question asked again has no more of it: Unbound does not restart a validation that went over
// its limits either (val_can_restart).
//
// NoReply says that a DS or DNSKEY lookup of the validation ended without a reply: the upstream
// resolver returned an error or timed out, after its own tries, for the first try of the lookup
// or for its second (see lookup). Whatever the verdict rests on, the same question asked again
// makes that lookup again and waits for it again: a reply that is Bogus with it is not asked for
// again.
type Verdict struct {
	Result    ValidationResult
	EDE       uint16    // The INFO-CODE, one of dns.ExtendedErrorCode*
	Text      string    // The EXTRA-TEXT
	Lifetimes Lifetimes // Of the RRsets of the answer and authority sections
	RanOut    bool      // The validation ran out of a budget
	NoReply   bool      // A DS or DNSKEY lookup of the validation got no reply
}

// newVerdict returns the verdict for a reply with the status result. err is why it is Bogus, if
// it is: the extendedError that err holds says what a client is told, and without one that is
// "DNSSEC Bogus". sections are the RRsets of the reply as validation left them, which say how long
// a Secure reply is authentic.
func newVerdict(result ValidationResult, err error, sections ...[]rrsetResult) Verdict {
	if result == ValidationResultSecure {
		return Verdict{Result: result, Lifetimes: newLifetimes(sections...)}
	}

	if result != ValidationResultBogus {
		return Verdict{Result: result}
	}

	why, told := errors.AsType[*extendedError](err)
	if !told {
		why = bogus("the reply failed validation")
	}

	return Verdict{Result: result, EDE: why.code, Text: why.text}
}

// Validate validates response as the reply to question according to RFC 4035 and returns its
// status:
//   - Secure: its answer section is the answer to the question, the zones of the RRsets of its
//     answer and authority sections signed them, each along a chain of trust from a trust anchor,
//     and what it denies is proven
//   - Insecure: a part of its answer is below a delegation that the parent zone proves to be
//     unsigned, and nothing is wrong with the rest
//   - Indeterminate: no trust anchor is above a name of its answer, and nothing is wrong with
//     the rest (RFC 4033 §5)
//   - Bogus: anything else. That includes a reply whose validation could not be completed, for
//     whatever reason (RFC 4035 §5.5, see classifyUndetermined): the verdict says why.
//
// The additional section is not validated, and nothing in it is read (RFC 4035 §3.2.3). Neither
// are the NS RRsets of the authority section that ValidatedAuthority leaves out. Validation does
// not change response.
//
// Parameters:
//   - ctx: Context for the validation operation
//   - response: DNS response message to validate
//   - question: The question that response is the reply to
func (v *Validator) Validate(ctx context.Context, response *dns.Msg, question dns.Question) Verdict {
	verdict, _ := v.verdict(ctx, response, question)

	return verdict
}

// ValidateResponse is Validate for a caller that needs the status of the reply only
func (v *Validator) ValidateResponse(
	ctx context.Context,
	response *dns.Msg,
	question dns.Question,
) ValidationResult {
	return v.Validate(ctx, response, question).Result
}

// verdict implements Validate and also returns the budget of the validation, which tells what it
// cost
func (v *Validator) verdict(ctx context.Context, response *dns.Msg, question dns.Question) (Verdict, *budget) {
	start := time.Now()
	v.logger.Debugf("DNSSEC validation requested for %s", question.Name)

	// Initialize query budget for this validation request (DoS protection); every sub-query of
	// the validation draws from it
	ctx = v.withBudget(ctx)

	verdict := v.responseStatus(ctx, response, question)

	// A validation that ran out of budget is incomplete. The response itself can force this, so
	// its answer is refused whether or not a trust anchor is above its names. A lookup that the
	// query budget refuses is one that could not be completed (see lookup).
	b := budgetFrom(ctx)
	if b.ranOut() {
		v.logger.Warnf("Validation of %s needs more signature verifications or NSEC3 hashes than one reply gets - "+
			"treating as Bogus", question.Name)

		verdict = newVerdict(ValidationResultBogus,
			bogus("validation needs more signature verifications or NSEC3 hashes than one reply gets"))
	}

	verdict.RanOut = verdict.Result == ValidationResultBogus && b.overdrawn()
	verdict.NoReply = b.unanswered()

	v.recordMetrics(start, verdict.Result)

	return verdict, b
}

// ValidatedAuthority returns the records of the authority section of response that the status of
// the reply covers: all but the NS RRsets that no RRSIG covers. A forwarder that holds the NS
// RRset of a zone without its RRSIG, from a referral, may add it to a reply that does not depend
// on it. A signed zone signs its NS RRset, so the reply would be Bogus with the RRset, and it
// says the same without. An NS RRset that is the only RRset of the authority section of a reply
// without answer is covered: such a reply has nothing else to say. Unbound takes the first such
// RRset out of a reply of a signed zone (remove_spurious_authority).
func ValidatedAuthority(response *dns.Msg) []dns.RR {
	if len(orderedRRsets(response.Answer)) == 0 && len(orderedRRsets(response.Ns)) == 1 {
		return response.Ns
	}

	sigs := rrsigsByRRset(response.Ns)

	return slices.DeleteFunc(slices.Clone(response.Ns), func(rr dns.RR) bool {
		return rr.Header().Rrtype == dns.TypeNS && len(sigs[rrsetKeyOf(rr)]) == 0
	})
}

// CoversNoRRset returns what reports whether a record is an RRSIG record that covers no RRset of
// rrs, the records of its section: none of them has its owner name and the type of its Type
// Covered field (RFC 4035 §5.3.1). Validation gives an RRset its status with the RRSIGs that
// cover it and does not read an RRSIG without its RRset (see validateSection), so the status of a
// reply says nothing of such a record.
func CoversNoRRset(rrs []dns.RR) func(dns.RR) bool {
	rrsets := groupRRsetsByNameAndType(rrs)

	return func(rr dns.RR) bool {
		sig, isSig := rr.(*dns.RRSIG)

		return isSig && len(rrsets[rrsetKey{name: dns.CanonicalName(sig.Hdr.Name), rrType: sig.TypeCovered}]) == 0
	}
}

// responseStatus returns the status of response as the reply to question. It is the status of
// the answer: the worst of the statuses of the RRsets of the chain that the answer section must
// be (see followAnswer) and, for a chain that ends without data, of the proof of that (see
// unansweredStatus). A name error for a chain that ends with data is Bogus: the name that has the
// data exists. The RRsets that the reply carries beside its answer, in the authority section and
// as the DNAME RRset above a CNAME, must be authentic for the reply to be (RFC 4035 §3.2.3). The
// additional section is no part of the reply's status.
//
// An RRset of either section that an RRSIG made for a wildcard verified is Bogus without the
// proof that the wildcard answers for its name, which the verified RRsets of the authority
// section give (see proveExpansions).
//
// The status comes as a verdict, which says why a reply is Bogus, and for how long each RRset of
// a Secure reply is authentic (see newVerdict).
func (v *Validator) responseStatus(ctx context.Context, response *dns.Msg, question dns.Question) Verdict {
	chain := followAnswer(response, question)

	switch {
	case chain.stray:
		v.logger.Warnf("Answer section holds an RRset that is no part of the answer for %s - treating as Bogus",
			question.Name)

		return newVerdict(ValidationResultBogus, bogus("the answer section holds an RRset that is no part of the answer"))
	case chain.found && response.Rcode == dns.RcodeNameError:
		v.logger.Warnf("Name error with the data asked for at %s - treating as Bogus", chain.end)

		return newVerdict(ValidationResultBogus, bogus("name error for %s, which has the data asked for", chain.end))
	}

	var authority []rrsetResult

	keys := chainKeys{v: v, parentSide: chain.parentSide}
	results := keys.validateAnswer(ctx, response.Answer, chain.synthesized)

	// An RRset that is Bogus for good makes the reply Bogus, so nothing after it is verified
	if !anyRefused(results) {
		authority = validateSection(ctx, ValidatedAuthority(response), keys)
		v.proveExpansions(ctx, authority, results, authority)
	}

	answer, beside := chain.split(results)
	beside = append(beside, authority...)
	status, why := worstStatus(answer), whyBogus(answer)

	if !chain.found && status != ValidationResultBogus && worstStatus(beside) != ValidationResultBogus {
		var proof ValidationResult

		nameError := response.Rcode == dns.RcodeNameError
		proof, why = v.unansweredStatus(ctx, authority, chain, question.Qtype, nameError)
		status = worst(status, proof)
	}

	// The reply has the status of its answer, which the RRsets beside the answer change in one
	// way: the reply is Bogus if one of them is, and if the answer is Secure and one of them is
	// not. They make no answer Insecure, and none better than it is.
	if rest := worstStatus(beside); rest == ValidationResultBogus ||
		status == ValidationResultSecure && rest != ValidationResultSecure {
		v.logger.Warnf("Reply for %s carries an RRset beside its answer that is %s - treating as Bogus",
			question.Name, rest.String())

		// A Bogus answer says why itself, and else the first Bogus RRset beside it does
		if status != ValidationResultBogus {
			if why = whyBogus(beside); why == nil {
				why = bogus("an RRset beside the authenticated answer is %s", rest.String())
			}
		}

		return newVerdict(ValidationResultBogus, why)
	}

	v.logger.Debugf("Reply for %s is %s", question.Name, status.String())

	return newVerdict(status, why, results, authority)
}

// answerChain is the answer that a reply gives to a question (see followAnswer)
type answerChain struct {
	synthesized map[rrsetKey]rrsetKey // CNAME -> DNAME supplying its exact substitution
	rrsets      map[rrsetKey]bool     // The RRsets of the chain
	end         string                // The name at which the chain ends, in canonical form
	found       bool                  // The chain ends with the RRsets asked for, and else at a name without them
	stray       bool                  // The answer section holds an RRset that the chain does not lead to

	// The CNAME RRset that answers a DS question, if the chain is that RRset: like the DS RRset
	// asked for, an RRset of the zone above its owner name (see holder)
	parentSide rrsetKey
}

// followAnswer follows the answer that reply gives to question (RFC 1034 §4.3.2): the chain from
// the query name along the CNAME RRsets of its answer section to the RRset of the query type. A
// query for CNAME takes the CNAME RRset of the query name as that RRset, and a query for ANY
// takes every RRset of the query name and follows no CNAME. An RRSIG is part of the RRset that it
// covers and no data by itself. Names are compared in canonical form (RFC 4034 §6.2).
//
// A query for DS asks the zone above a name whether the name is a zone cut (RFC 4035 §2.4). A
// name that owns a CNAME RRset has no other data (RFC 1034 §3.6.2, RFC 2181 §10.1), so it is
// none, and that RRset is all that the zone above has to answer with: the chain of trust walk
// reads it so too (see ownsCNAME). What the target of the CNAME has is another question. So the
// CNAME RRset of the query name is the RRset asked for if the reply ends with it: the answer
// section holds no other RRset, and the reply says nothing of the target (see endsWithAnswer).
// It is then an RRset of the zone above the name, as the DS RRset would be (see holder). A reply
// that goes on says what the target has, and the chain follows it there as for any other type.
//
// The rule is for the CNAME RRset that the name owns. One that a wildcard gives the query name
// comes with the NSEC or NSEC3 records that prove so, in a reply that therefore does not end with
// its answer: it is validated as one that goes on.
//
// A CNAME made from a DNAME comes with the DNAME RRset of a name above it (RFC 6672 §3.1). That
// RRset supplies the unsigned CNAME if the substitution is exact. Every other RRset that the
// chain does not lead to is a stray: such a section answers another question, or none.
func followAnswer(reply *dns.Msg, question dns.Question) answerChain {
	rest := groupRRsetsByNameAndType(reply.Answer)
	chain := answerChain{rrsets: make(map[rrsetKey]bool), end: dns.CanonicalName(question.Name)}
	dnames := indexDNAMEs(rest)
	if len(dnames) != 0 {
		chain.synthesized = make(map[rrsetKey]rrsetKey)
	}

	// take moves the RRset of the name at the end of the chain with the type rrType into the
	// chain. An RRset is taken once, so the chain ends where its CNAMEs loop.
	take := func(rrType uint16) []dns.RR {
		key := rrsetKey{name: chain.end, rrType: rrType}

		rrset, held := rest[key]
		if held {
			delete(rest, key)
			chain.rrsets[key] = true
		}

		if held && rrType == dns.TypeCNAME && len(dnames) != 0 {
			chain.takeCoveringDNAME(key, rrset, dnames, rest)
		}

		return rrset
	}

	if question.Qtype == dns.TypeANY {
		for key := range rest {
			if key.name == chain.end {
				take(key.rrType)

				chain.found = true
			}
		}
	}

	for question.Qtype != dns.TypeANY {
		if take(question.Qtype) != nil {
			chain.found = true

			break
		}

		target, isAlias := cnameTarget(take(dns.TypeCNAME))
		if !isAlias {
			break
		}

		// The CNAME RRset of the query name is the answer to a DS question that the reply takes no
		// further
		if question.Qtype == dns.TypeDS && len(chain.rrsets) == 1 && len(rest) == 0 && endsWithAnswer(reply) {
			chain.found, chain.parentSide = true, rrsetKey{name: chain.end, rrType: dns.TypeCNAME}

			break
		}

		chain.end = target
	}

	chain.stray = chain.stray || len(rest) > 0

	return chain
}

// Keep DNAMEs available for later substitutions even after they have been taken from rest.
func indexDNAMEs(rest map[rrsetKey][]dns.RR) map[rrsetKey][]dns.RR {
	var dnames map[rrsetKey][]dns.RR
	for key, rrset := range rest {
		if key.rrType != dns.TypeDNAME {
			continue
		}
		if dnames == nil {
			dnames = make(map[rrsetKey][]dns.RR)
		}
		dnames[key] = rrset
	}

	return dnames
}

func (chain *answerChain) takeCoveringDNAME(key rrsetKey, rrset []dns.RR, dnames, rest map[rrsetKey][]dns.RR) {
	// Walk whole DNS labels: a quoted dot belongs to its label. Only the closest DNAME applies.
	for off, end := dns.NextLabel(key.name, 0); !end; off, end = dns.NextLabel(key.name, off) {
		above := rrsetKey{key.name[off:], dns.TypeDNAME}
		ds := dnames[above]
		if ds == nil {
			continue
		}

		if matchesDNAME(key.name[:off], ds, rrset) {
			chain.synthesized[key] = above
			delete(rest, above)
		} else {
			chain.stray = true
		}

		return
	}
}

// matchesDNAME checks RFC 6672 §3.1: preserve every label below the DNAME owner
// and replace only that owner with the DNAME target (possibly the root).
func matchesDNAME(prefix string, ds, cs []dns.RR) bool {
	if len(ds) != 1 || len(cs) != 1 {
		return false
	}
	d, dok := ds[0].(*dns.DNAME)
	c, cok := cs[0].(*dns.CNAME)
	if !dok || !cok || d.Hdr.Class != c.Hdr.Class {
		return false
	}
	target := prefix
	if d.Target != "." {
		target += dns.CanonicalName(d.Target)
	}
	_, valid := dns.IsDomainName(target)

	return valid && target == dns.CanonicalName(c.Target)
}

// endsWithAnswer reports whether reply says nothing beyond its answer section about the name
// that the section leads to: it is no name error, and its authority section holds no RRset that
// is validated (see ValidatedAuthority). Such a reply neither names what that name has nor denies
// it.
func endsWithAnswer(reply *dns.Msg) bool {
	return reply.Rcode == dns.RcodeSuccess && len(orderedRRsets(ValidatedAuthority(reply))) == 0
}

// cnameTarget returns the name that rrset, a CNAME RRset, points to, in canonical form. A name
// has one CNAME record (RFC 2181 §10.1), so it is the target of the first.
func cnameTarget(rrset []dns.RR) (target string, isAlias bool) {
	if len(rrset) == 0 {
		return "", false
	}

	cname, isAlias := rrset[0].(*dns.CNAME)
	if !isAlias {
		return "", false
	}

	return dns.CanonicalName(cname.Target), true
}

// split returns the RRsets of results, those of the answer section, that are part of the chain,
// and the others
func (c answerChain) split(results []rrsetResult) (answer, beside []rrsetResult) {
	for _, r := range results {
		if c.rrsets[rrsetKeyOf(r.rrs[0])] {
			answer = append(answer, r)
		} else {
			beside = append(beside, r)
		}
	}

	return answer, beside
}

// unansweredStatus returns the status of chain, an answer that ends at a name without an RRset
// of qtype. authority holds the RRsets of the authority section of the reply, none of them Bogus.
// The zone that holds the missing RRset gives the denial (RFC 4035 §5.4): its NSEC or NSEC3
// records in the reply (see denialZone) must prove what the reply says, for a name error that the
// name does not exist, and else that it has no RRset of qtype. For a name behind a CNAME, a reply
// without name error may say either (RFC 2308 §2.2.1, RFC 6604 §3).
//
// An answer that no zone proves so has the status of unsigned data at the name where it ends:
// Insecure only below a proven insecure delegation (RFC 4035 §4.3), and Bogus in a Secure zone,
// which denies what it does not have. Only Secure NSEC and NSEC3 records are a proof: what another
// one is says nothing about that name. The error says why the status is Bogus.
func (v *Validator) unansweredStatus(
	ctx context.Context, authority []rrsetResult, chain answerChain, qtype uint16, nameError bool,
) (ValidationResult, error) {
	// The RRset that the answer ends without
	missing := rrsetResult{owner: chain.end, rrType: qtype}
	proof := ValidationResultBogus

	if zone, found := v.denialZone(authority, v.holder(&missing)); found {
		d := v.newDenialSet(ctx, zone, authority, chain.end, qtype)
		behindCNAME := len(chain.rrsets) > 0

		switch {
		case nameError:
			proof = d.nameError()
		case behindCNAME:
			if proof = d.noData(); proof == ValidationResultBogus {
				proof = d.nameError()
			}
		default:
			proof = d.noData()
		}
	}

	if proof == ValidationResultBogus {
		v.logger.Debugf("No proof for %s, which has no data of type %d", chain.end, qtype)

		return v.unsignedDataStatus(ctx, &missing)
	}

	return proof, nil
}

// holder returns the name whose zone holds r: the owner name of r, or the name above it if r is
// on the parent's side of a zone cut at its owner name. That is a DS RRset (RFC 4035 §2.4), the
// CNAME RRset that answers a question for one (see followAnswer), and the NSEC record of a
// delegation, which lists what the zone above has at the name (RFC 6840 §4.1). The root has no
// zone above it. An NSEC3 record is held by the zone that its owner name names after the hash
// (RFC 5155 §3). r may be an RRset that a reply lacks: an owner name and a type.
func (v *Validator) holder(r *rrsetResult) string {
	parentSide := r.parentSide || r.rrType == dns.TypeDS

	if len(r.rrs) > 0 {
		switch rr := r.rrs[0].(type) {
		case *dns.NSEC3:
			return nsec3Zone(rr)
		case *dns.NSEC:
			parentSide = isDelegation(rr.TypeBitMap)
		}
	}

	if parent := v.getParentDomain(r.owner); parentSide && parent != "" {
		return parent
	}

	return r.owner
}

// unsignedDataStatus returns the status of r, an RRset that has no RRSIG: that of the zone that
// holds it (see holder), which the chain of trust walk finds (see walk). Per RFC 4035 §5.2 the
// absence of signatures only means "insecure" if the name is provably below an insecure
// delegation. If the zone is secure (chains to a trust anchor) with no authenticated proof of an
// insecure delegation, unsigned data is bogus, not insecure: a signed zone signs all that it
// holds, and proves what it does not hold. A walk that could not be completed says nothing about
// the zone (see classifyUndetermined). The error says why the status is Bogus.
func (v *Validator) unsignedDataStatus(ctx context.Context, r *rrsetResult) (ValidationResult, error) {
	name := v.holder(r)
	zone := v.walk(ctx, name, false)

	switch zone.result {
	case ValidationResultSecure:
		v.logger.Warnf("No RRSIG for %s but zone is secure - treating unsigned answer as bogus", r.owner)

		if len(r.rrs) == 0 {
			return ValidationResultBogus, bogus("no proof that %s has no %s RRset", r.owner, dns.Type(r.rrType))
		}

		return ValidationResultBogus, &extendedError{
			code: dns.ExtendedErrorCodeRRSIGsMissing,
			text: fmt.Sprintf("no RRSIG for %s %s in a signed zone", r.owner, dns.Type(r.rrType)),
		}
	case ValidationResultIndeterminate:
		return v.classifyUndetermined(name, zone.err)
	case ValidationResultInsecure, ValidationResultBogus:
		// Below an insecure delegation, or in a zone that is Bogus itself
		v.logger.Debugf("No RRSIG for %s - zone status %s", r.owner, zone.result.String())
	}

	return zone.result, zone.err
}

// recordMetrics records validation metrics
func (v *Validator) recordMetrics(start time.Time, result ValidationResult) {
	duration := time.Since(start)
	v.validationMetrics.WithLabelValues(result.String()).Inc()
	v.validationDuration.WithLabelValues(result.String()).Observe(duration.Seconds())
}

// rrsetKey uniquely identifies an RRset by owner name and type
// Per RFC 4035: An RRset is a set of RRs with the same owner name, class, and type
type rrsetKey struct {
	name   string // Owner name in canonical form (RFC 4034 §6.2)
	rrType uint16 // Record type
}

// rrsetKeyOf returns the key of the RRset that rr is part of. Owner names that differ in case are
// one name (RFC 4343), so the key holds the name in canonical form.
func rrsetKeyOf(rr dns.RR) rrsetKey {
	return rrsetKey{name: dns.CanonicalName(rr.Header().Name), rrType: rr.Header().Rrtype}
}

// groupRRsetsByNameAndType groups RRs by their owner name and type (excluding RRSIGs)
// This is critical for DNSSEC validation: each RRset must contain only records
// with the same owner name. For CNAME chains, each CNAME is a separate RRset.
// A record that spells the owner name in another case than the first record of its RRset joins
// the RRset as a copy with the spelling of the first: miekg/dns verifies an RRset only if its
// records spell the name alike.
func groupRRsetsByNameAndType(rrs []dns.RR) map[rrsetKey][]dns.RR {
	rrsets := make(map[rrsetKey][]dns.RR)
	for _, rr := range rrs {
		if _, isSig := rr.(*dns.RRSIG); !isSig {
			key := rrsetKeyOf(rr)
			if rrset := rrsets[key]; len(rrset) > 0 && rr.Header().Name != rrset[0].Header().Name {
				rr = dns.Copy(rr)
				rr.Header().Name = rrset[0].Header().Name
			}

			rrsets[key] = append(rrsets[key], rr)
		}
	}

	return rrsets
}

// orderedRRsets returns the RRsets of rrs in the order of their first records
func orderedRRsets(rrs []dns.RR) [][]dns.RR {
	grouped := groupRRsetsByNameAndType(rrs)
	rrsets := make([][]dns.RR, 0, len(grouped))

	for _, rr := range rrs {
		key := rrsetKeyOf(rr)
		if rrset, pending := grouped[key]; pending {
			rrsets = append(rrsets, rrset)

			delete(grouped, key)
		}
	}

	return rrsets
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

// hasTrustAnchorBelow reports whether a trust anchor covers name below signer, an ancestor of
// name. The zone of that anchor, not signer, then has to sign what the zone of name holds (see
// holder).
func (v *Validator) hasTrustAnchorBelow(signer, name string) bool {
	signer = dns.CanonicalName(signer)

	for name = dns.CanonicalName(name); name != signer && name != ""; name = v.getParentDomain(name) {
		if v.trustAnchors.HasTrustAnchor(name) {
			return true
		}
	}

	return false
}

// classifyUndetermined returns the status of data for which the chain of trust walk to the zone
// of name came back Indeterminate: the zone that an RRSIG names as the signer of the data, or
// the zone that holds the data without RRSIG. why says which lookup of the walk could not be
// completed (see lookup), if the walk made one.
//
// A name with a trust anchor above it, the default root anchor included, is in a secure part of
// the tree until an authenticated denial says otherwise (RFC 4035 §5.2, GHSA-x845-2f78-7v36). If
// the records that validate data there cannot be obtained, for whatever reason, the data is not
// validated and is Bogus (RFC 4035 §5.5), with RRSIG as without: whoever answers the lookups, or
// keeps them from being answered, does not decide that a reply is served. Only a name with no
// trust anchor above it is Indeterminate (RFC 4033 §5), and no lookup is made for it. Neither
// status is cached: the next validation walks again, and finds what the zone is once its lookups
// are answered (issue #2120). The error says why the data is not validated.
func (v *Validator) classifyUndetermined(name string, why error) (ValidationResult, error) {
	name = dns.Fqdn(name)

	if !v.isUnderTrustAnchor(name) {
		v.logger.Debugf("Zone of %s indeterminate (no trust anchor in hierarchy)", name)

		return ValidationResultIndeterminate, fmt.Errorf("no trust anchor at or above %s", name)
	}

	v.logger.Debugf("Chain of trust to %s could not be completed under a trust anchor - treating as Bogus: %v",
		name, why)

	return ValidationResultBogus, errors.Join(why, bogus("the chain of trust to %s could not be completed", name))
}
