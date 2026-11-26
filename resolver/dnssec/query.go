package dnssec

// This file contains upstream query management and DoS protection logic.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

// queryBudgetKey is the context key for tracking upstream query budget
type queryBudgetKey struct{}

// clientContextKey is the context key carrying the originating client's identity so
// that DNSSEC auxiliary (DS/DNSKEY) sub-queries resolve from the same upstream view
// as the user-facing answer.
type clientContextKey struct{}

// clientContext holds the originating client's identity for DNSSEC sub-queries and the
// upstream view that answers them.
type clientContext struct {
	ip       net.IP
	names    []string
	clientID string
	view     string
}

// WithClientContext returns a context carrying the originating client's identity so
// DNSSEC auxiliary queries issued during validation preserve it. view names the upstream
// group those queries reach; validation results are cached per view. Called by the DNSSEC
// resolver before validating a response.
func WithClientContext(ctx context.Context, ip net.IP, names []string, clientID, view string) context.Context {
	return context.WithValue(ctx, clientContextKey{},
		clientContext{ip: ip, names: names, clientID: clientID, view: view})
}

// clientContextFrom extracts the originating client's identity from the context.
func clientContextFrom(ctx context.Context) (clientContext, bool) {
	cc, ok := ctx.Value(clientContextKey{}).(clientContext)

	return cc, ok
}

// askKey is the context key for which of the two replies to a question a validation is for (see
// FirstAsk)
type askKey struct{}

// ask says that a validation is that of the first reply to a question that is asked once more if
// that reply is Bogus, or that of the second. spent is what the two share: the budget of the
// first validation, which the second goes on with (see withBudget).
type ask struct {
	second bool
	spent  *spentBudget
}

// spentBudget is the budget of a validation as the next validation for the same client query
// finds it: the upstream queries that are left, and the rest (see budget)
type spentBudget struct {
	queries *atomic.Int64
	work    *budget
}

// FirstAsk returns the context for validating the first reply to a question that is asked once
// more if validation finds that reply Bogus (see Again). A reply that fails validation says that
// the reply is bad, not that the name is, and the same holds for the replies to the DS and DNSKEY
// queries of the walk: one that came and does not verify, a DNSKEY RRset without its RRSIG, say,
// makes its zone Bogus. So this validation stores no Bogus zone status (see
// setCachedZoneStatus): the validation of the second reply walks to that zone again, and what it
// finds is what the cache holds. It takes two replies to fail a zone for other validations.
func FirstAsk(ctx context.Context) context.Context {
	return context.WithValue(ctx, askKey{}, ask{spent: new(spentBudget)})
}

// Again returns the context for validating the second reply to a question, from ctx, the context
// that its first reply was validated in (see FirstAsk). The two validations are those of one
// client query, which has one budget: the second goes on with the signature verifications, NSEC3
// hashes and upstream queries that the first one left (see withBudget). It walks again to the
// zones of the signers, and makes again the lookups that the first could not complete.
func Again(ctx context.Context) context.Context {
	first, _ := ctx.Value(askKey{}).(ask)
	if first.spent == nil {
		first.spent = new(spentBudget)
	}

	return context.WithValue(ctx, askKey{}, ask{second: true, spent: first.spent})
}

// asksAgain reports whether ctx is that of a validation after which the question is asked once
// more if the reply is Bogus (see FirstAsk)
func asksAgain(ctx context.Context) bool {
	asked, twice := ctx.Value(askKey{}).(ask)

	return twice && !asked.second
}

// withBudget returns the context of the validation that ctx is for, with its budget (see
// withQueryBudget). The validation of the second reply to a question goes on with the budget of
// the validation of the first (see Again): what that one spent is spent, and what it found for a
// signer zone or could not look up is forgotten.
func (v *Validator) withBudget(ctx context.Context) context.Context {
	asked, _ := ctx.Value(askKey{}).(ask)
	if asked.spent != nil && asked.spent.work != nil {
		asked.spent.work.forget()

		return context.WithValue(context.WithValue(ctx, queryBudgetKey{}, asked.spent.queries),
			budgetKey{}, asked.spent.work)
	}

	ctx = withQueryBudget(ctx, int(v.maxUpstreamQueries))

	if asked.spent != nil {
		asked.spent.queries, _ = ctx.Value(queryBudgetKey{}).(*atomic.Int64)
		asked.spent.work = budgetFrom(ctx)
	}

	return ctx
}

// withQueryBudget returns the context of one validation. Its upstream queries, and those of every
// context derived from it, share a budget of n queries, and its signature verifications and NSEC3
// hashes share the budget that budgetFrom returns. One call makes both, so that no context can
// query without a limit on what its replies cost.
func withQueryBudget(ctx context.Context, n int) context.Context {
	queries := new(atomic.Int64)
	queries.Store(int64(n))

	return context.WithValue(context.WithValue(ctx, queryBudgetKey{}, queries), budgetKey{}, new(budget))
}

// consumeQueryBudget takes one query from the budget and returns error if budget is exhausted
// This provides DoS protection by limiting the number of upstream queries that the validations of
// one client query make (see withBudget)
func (v *Validator) consumeQueryBudget(ctx context.Context) error {
	budget, ok := ctx.Value(queryBudgetKey{}).(*atomic.Int64)
	if !ok {
		// Budget not initialized - this shouldn't happen but fail safely
		return errors.New("query budget not initialized")
	}

	// A validation that has run out of budget asks for nothing more
	if budgetFrom(ctx).ranOut() {
		return errBudgetExhausted
	}

	if budget.Add(-1) < 0 {
		budgetFrom(ctx).queryRefused()

		return fmt.Errorf("upstream query budget exhausted (max: %d queries per client query)", v.maxUpstreamQueries)
	}

	return nil
}

// The work that a reply may cost (KeyTrap, CVE-2023-50387; NSEC3 hashing, CVE-2023-50868)
const (
	// maxRRsetVerifications is the number of tries, each of one RRSIG with one key, that an RRset
	// gets, whatever key source verifies it (Unbound's MAX_VALIDATE_RRSIGS)
	maxRRsetVerifications = 8

	// maxVerifications is the number of signatures that one ValidateResponse call verifies, for
	// the reply that it validates and for the replies to its DS and DNSKEY queries together
	maxVerifications = 128

	// maxNSEC3Hashes is the number of NSEC3 hashes that one ValidateResponse call computes, each
	// with at most the configured number of iterations (RFC 5155 §10.3, RFC 9276 §3.2)
	maxNSEC3Hashes = 128
)

var (
	// errBudgetExhausted says that a validation asked for more work than its budget holds
	errBudgetExhausted = errors.New("validation budget exhausted")

	// errNoBudget says that work was asked for in a context that withQueryBudget did not make
	errNoBudget = errors.New("validation budget not initialized")

	// errNoReply says that upstream gave no reply to a query: an error, or a timeout
	errNoReply = errors.New("upstream query failed")

	// errTruncated says that the reply to a query came truncated
	errTruncated = errors.New("truncated reply")
)

// budgetKey is the context key for the budget of a validation
type budgetKey struct{}

// budget is the work that one ValidateResponse call may do for the reply that it validates and
// for the replies to its own DS and DNSKEY queries together: maxVerifications signature
// verifications and maxNSEC3Hashes NSEC3 hash computations. A validation that asks for more has
// run out of budget. Its reply is Bogus, and what it finds from then on says how much work the
// reply asked for and nothing about a zone, so none of it is kept (see setCachedZoneStatus).
//
// The budget also holds what the validation works out once and uses again. A context that
// belongs to no validation has no budget (budgetFrom returns nil), which is a budget that has
// run out: nothing is tried, hashed or kept for it (see ranOut).
type budget struct {
	verifications atomic.Int64 // The signatures verified
	hashes        atomic.Int64 // The NSEC3 hashes computed
	exhausted     atomic.Bool  // A try at a verification or a hash was asked for and refused
	noQueryLeft   atomic.Bool  // An upstream query was asked for and refused (see consumeQueryBudget)

	mu          sync.Mutex
	nsec3Hashes map[nsec3HashKey]string // The NSEC3 hashes computed so far
	keyTags     map[*dns.DNSKEY]uint16  // The key tags computed so far
	signers     map[string]signerZone   // The signer zones walked to so far, by canonical name
	lookups     map[lookupKey]error     // The lookups that could not be completed so far, and why
}

// nsec3HashKey identifies an NSEC3 hash: a name in lower case and the parameters it is hashed
// with. The hash algorithm is not one of them: every caller has checked that it is SHA-1.
type nsec3HashKey struct {
	name       string
	salt       string
	iterations uint16
}

// signerZone is what a validation found for a zone that RRSIGs name as their signer: its status,
// if that is Secure its validated keys, and else why the walk did not get there (see zoneStatus)
type signerZone struct {
	result ValidationResult
	keys   keySet
	err    error
}

// lookupKey names a lookup of the chain of trust walk: the RRset of a type, DS or DNSKEY, that
// name owns, a name in canonical form
type lookupKey struct {
	name  string
	qtype uint16
}

// budgetFrom returns the budget of the validation that ctx belongs to, or nil if withQueryBudget
// did not make ctx
func budgetFrom(ctx context.Context) *budget {
	b, _ := ctx.Value(budgetKey{}).(*budget)

	return b
}

// ranOut reports whether the validation has run out of budget. Without a budget it has none
// left either.
func (b *budget) ranOut() bool {
	return b == nil || b.exhausted.Load()
}

// queryRefused notes that the validation asked for an upstream query when it had none left
func (b *budget) queryRefused() {
	if b != nil {
		b.noQueryLeft.Store(true)
	}
}

// overdrawn reports whether the validation asked for more than it had of one of its three
// budgets: signature verifications, NSEC3 hashes or upstream queries
func (b *budget) overdrawn() bool {
	return b.ranOut() || b != nil && b.noQueryLeft.Load()
}

// forget drops what the validation found for signer zones and which lookups it could not
// complete, for a validation that goes on with the budget (see withBudget)
func (b *budget) forget() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.signers, b.lookups = nil, nil
}

// tryLeft reports whether an RRSIG of the RRset of r may still be tried: the RRset has had fewer
// than maxRRsetVerifications tries, and the validation has not run out of budget
func (b *budget) tryLeft(r *rrsetResult) bool {
	return r.tries < maxRRsetVerifications && !b.ranOut()
}

// spendTry takes one try at verifying the RRset of r, of one RRSIG with one key. It returns why
// there is none: the RRset has had its maxRRsetVerifications tries, or the validation has
// verified its maxVerifications signatures and so has run out of budget (errBudgetExhausted),
// now or before.
func (b *budget) spendTry(r *rrsetResult) error {
	switch {
	case b == nil:
		return errNoBudget
	case r.tries >= maxRRsetVerifications:
		return errors.New("no signature verifications left")
	case b.exhausted.Load() || b.verifications.Load() >= maxVerifications:
		b.exhausted.Store(true)

		return errBudgetExhausted
	}

	r.tries++

	return nil
}

// spendVerification counts a signature that a try verifies
func (b *budget) spendVerification() {
	if b != nil {
		b.verifications.Add(1)
	}
}

// nsec3Hash returns the NSEC3 hash of name (see nsec3Hash). The validation computes each hash
// once, however many records and proofs ask for it, and that takes one of its maxNSEC3Hashes.
// Without one left the hash is empty, like that of a name that cannot be hashed.
func (b *budget) nsec3Hash(name, salt string, iterations uint16) string {
	if b == nil {
		return ""
	}

	key := nsec3HashKey{name: dns.Fqdn(strings.ToLower(name)), salt: salt, iterations: iterations}

	b.mu.Lock()
	defer b.mu.Unlock()

	hash, known := b.nsec3Hashes[key]

	switch {
	case known:
	case b.exhausted.Load() || b.hashes.Load() >= maxNSEC3Hashes:
		b.exhausted.Store(true)
	default:
		hash = nsec3Hash(key.name, salt, iterations)

		if b.nsec3Hashes == nil {
			b.nsec3Hashes = make(map[nsec3HashKey]string)
		}

		b.nsec3Hashes[key] = hash
		b.hashes.Add(1)
	}

	return hash
}

// keyTag returns the key tag of key (RFC 4034 Appendix B). The validation computes it once,
// however many key sets hold the key.
func (b *budget) keyTag(key *dns.DNSKEY) uint16 {
	if b == nil {
		return key.KeyTag()
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	tag, known := b.keyTags[key]
	if !known {
		tag = key.KeyTag()

		if b.keyTags == nil {
			b.keyTags = make(map[*dns.DNSKEY]uint16)
		}

		b.keyTags[key] = tag
	}

	return tag
}

// signer returns what the validation found for the signer zone name, a name in canonical form,
// when walk went there, which it does once: an RRSIG that names a zone the validation has been
// to costs no further walk, whatever the walk found.
func (b *budget) signer(name string, walk func() signerZone) signerZone {
	if b == nil {
		return walk()
	}

	b.mu.Lock()
	zone, known := b.signers[name]
	b.mu.Unlock()

	if !known {
		zone = walk()

		b.mu.Lock()
		defer b.mu.Unlock()

		if b.signers == nil {
			b.signers = make(map[string]signerZone)
		}

		b.signers[name] = zone
	}

	return zone
}

// failedLookup returns why the validation could not complete the lookup key, or nil if it has not
// failed at it
func (b *budget) failedLookup(key lookupKey) error {
	if b == nil {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	return b.lookups[key]
}

// unanswered reports whether a lookup of the validation ended without a reply from upstream, at
// its first try or at its second (see lookup)
func (b *budget) unanswered() bool {
	if b == nil {
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for _, err := range b.lookups {
		if errors.Is(err, errNoReply) {
			return true
		}
	}

	return false
}

// lookupFailed keeps err as why the validation could not complete the lookup key
func (b *budget) lookupFailed(key lookupKey, err error) {
	if b == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.lookups == nil {
		b.lookups = make(map[lookupKey]error)
	}

	b.lookups[key] = err
}

// lookup asks upstream for the DS or DNSKEY RRset of name, for the chain of trust walk, and
// returns the reply. It returns an error if the lookup could not be completed: upstream gave no
// reply, or one that does not answer the query (see incomplete). What such a lookup leaves open
// is for classifyUndetermined to say. Nothing of it is cached, so the next validation asks again
// (issue #2120).
//
// A reply that came and does not answer is asked for once more, which gives a resolver that
// failed for a moment, or another one of the upstream group, the chance to answer. A query
// without reply is not repeated: the upstream resolver made its own tries. So a lookup ends
// without a reply when its first try gets none, or its second after a first reply that did not
// answer, and the question of the client is not asked again after it either (see Verdict). Every
// try takes a query of the validation's budget. A lookup that failed is not made again by the
// validation, so it costs two queries however many RRsets need its zone.
func (v *Validator) lookup(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	const tries = 2

	b, key := budgetFrom(ctx), lookupKey{name: dns.CanonicalName(name), qtype: qtype}

	err := b.failedLookup(key)
	if err != nil {
		return nil, err
	}

	for range tries {
		reply, failed := v.queryRecords(ctx, key.name, qtype)
		if err = key.incomplete(reply, failed); err == nil {
			return reply, nil
		}

		if failed != nil && !errors.Is(failed, errTruncated) {
			break
		}
	}

	b.lookupFailed(key, err)

	return nil, err
}

// incomplete returns why a query for the RRset of key does not complete the lookup, with what a
// client is told of that (RFC 8914 §4), or nil if it does. failed is why the query got no reply
// to read, and else reply is what it got:
//   - No reply, or a truncated one. A query that the validation had none left for is neither.
//   - A reply with an RCODE that reports an error, which is neither an answer nor a name error:
//     a network error for a DS RRset (Unbound's ds_response_to_ke), missing keys for a DNSKEY
//     RRset.
//   - For a DNSKEY RRset, a reply that does not hold it. A zone that is asked for its keys has
//     them, so such a reply says that the upstream did not get them, not that there are none.
//     Unbound asks again for it too (process_dnskey_response).
//   - For a DS RRset, a reply that holds neither an RRset of the name that answers the query, DS
//     or CNAME (see handleDSAbsence), nor NSEC or NSEC3 records: nothing about the name, and no
//     denial.
func (key lookupKey) incomplete(reply *dns.Msg, failed error) error {
	query := dns.TypeToString[key.qtype] + " query for " + key.name
	told := func(code uint16, text string) error {
		return &extendedError{code: code, text: text + " the " + query, cause: failed}
	}

	switch {
	case errors.Is(failed, errNoReply):
		return told(dns.ExtendedErrorCodeNoReachableAuthority, "no reply to")
	case errors.Is(failed, errTruncated):
		return told(dns.ExtendedErrorCodeNetworkError, "truncated reply to")
	case failed != nil:
		return told(dns.ExtendedErrorCodeDNSBogus, "no upstream query left for")
	}

	holds := func(rrType uint16) bool { return len(answerRecords(reply, key.name, rrType)) > 0 }

	rcode, named := dns.RcodeToString[reply.Rcode]
	if !named {
		rcode = "RCODE " + strconv.Itoa(reply.Rcode)
	}

	switch {
	case reply.Rcode != dns.RcodeSuccess && reply.Rcode != dns.RcodeNameError:
		if key.qtype == dns.TypeDNSKEY {
			return told(dns.ExtendedErrorCodeDNSKEYMissing, rcode+" reply to")
		}

		return told(dns.ExtendedErrorCodeNetworkError, rcode+" reply to")
	case key.qtype == dns.TypeDNSKEY && !holds(dns.TypeDNSKEY):
		return told(dns.ExtendedErrorCodeDNSKEYMissing, "no records of the DNSKEY RRset in the reply to")
	case key.qtype == dns.TypeDNSKEY, holds(dns.TypeDS), holds(dns.TypeCNAME), hasDenialRecords(reply.Ns):
		return nil
	}

	return told(dns.ExtendedErrorCodeNSECMissing, "neither the DS RRset nor its denial in the reply to")
}

// queryRecords performs a DNS query for a specific record type with DNSSEC enabled
func (v *Validator) queryRecords(ctx context.Context, domain string, qtype uint16) (*dns.Msg, error) {
	// Check query budget (DoS protection)
	if err := v.consumeQueryBudget(ctx); err != nil {
		v.logger.Warnf("Query budget exhausted while querying %s (type %d): %v", domain, qtype, err)

		return nil, err
	}

	domain = dns.Fqdn(domain)

	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(domain, qtype)
	msg.SetEdns0(ednsUDPSize, true) // Set DO bit for DNSSEC
	// Set the CD (Checking Disabled) bit so a validating upstream does not pre-filter these
	// auxiliary DS/DNSKEY lookups: we must validate the RAW records ourselves. Without it an
	// upstream like 8.8.8.8 returns SERVFAIL for a bogus chain (e.g. dnssec-failed.org), which
	// we could not distinguish from an unreachable upstream - a lookup that could not be completed
	// instead of records that are rejected as Bogus. This is what makes validation independent
	// (#1287).
	msg.CheckingDisabled = true

	// Create model request, preserving the originating client's identity so the
	// upstream tree selects the same group/view as the user-facing answer.
	req := &model.Request{
		Req:      msg,
		Protocol: model.RequestProtocolUDP,
	}
	if cc, ok := clientContextFrom(ctx); ok {
		req.ClientIP = cc.ip
		req.ClientNames = cc.names
		req.RequestClientID = cc.clientID
	}

	// Query upstream
	response, err := v.upstream.Resolve(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNoReply, err)
	}

	// The upstream keeps a truncated UDP reply when its TCP retry fails. Records may be missing
	// from it, so it counts as a failed query, not as an answer without them.
	if response.Res.Truncated {
		return nil, fmt.Errorf("upstream query failed: %w for %s", errTruncated, domain)
	}

	return response.Res, nil
}

// answerRRset returns the RRset of name and rrType that reply, the reply to a query about name,
// answers with: the records of that name and type in its answer section, with the status that ks
// gives them from the RRSIGs that cover them there, as validateSection gives every RRset of a
// section its status. It returns nil if the section has no such record. rrType is the type that
// was asked for, or CNAME: a name that owns a CNAME RRset answers a query for any other type
// with that RRset (RFC 1034 §3.6.2).
//
// Nothing else in the reply is an RRset of the name asked about. A DS RRset is that of the
// delegation that owns it, the keys of a zone are the DNSKEY RRset at its apex (RFC 4034 §2 and
// §5, RFC 4035 §5.2), and a name owns the CNAME RRset that it has, so records of another owner
// name say nothing about name, whoever signed them. Nor do the records of a wildcard under that
// name: no RRSIG made for a wildcard verifies a DS or DNSKEY RRset (see verifyRRset), and an RRset
// of another type that only such an RRSIG verifies is Bogus (see verifiedBy).
func answerRRset(ctx context.Context, reply *dns.Msg, name string, rrType uint16, ks keySource) *rrsetResult {
	rrset := answerRecords(reply, name, rrType)
	if len(rrset) == 0 {
		return nil
	}

	r := newRRsetResult(rrset)
	ks.verify(ctx, &r, rrsigsByRRset(reply.Answer)[rrsetKeyOf(rrset[0])])

	return &r
}

// answerRecords returns the records of name and rrType in the answer section of reply
func answerRecords(reply *dns.Msg, name string, rrType uint16) []dns.RR {
	return groupRRsetsByNameAndType(reply.Answer)[rrsetKey{name: dns.CanonicalName(name), rrType: rrType}]
}

// dnskeyRRset looks up the DNSKEY RRset of zone and returns what the reply answers: the DNSKEY
// RRset of zone with the status that ks gives it (see answerRRset)
func (v *Validator) dnskeyRRset(ctx context.Context, zone string, ks keySource) (*rrsetResult, error) {
	response, err := v.lookup(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		// The lookup could not be completed (see lookup), which is no proof of an invalid
		// signature: errDNSKEYUnavailable says so
		return nil, fmt.Errorf("%w: %w", errDNSKEYUnavailable, err)
	}

	// A lookup that is completed has the DNSKEY RRset of the zone in its reply
	return answerRRset(ctx, response, zone, dns.TypeDNSKEY, ks), nil
}
