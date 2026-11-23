package resolver

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/resolver/dnssec"
	"github.com/0xERR0R/blocky/util"
	expirationcache "github.com/0xERR0R/expiration-cache"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	// ednsUDPSize is the EDNS0 UDP buffer size
	ednsUDPSize = 4096

	// failureCacheSize is the number of questions that the cache of validation failures holds (see
	// refused): a resolver limits the memory of that cache (RFC 9520 §3.2). The questions of
	// clients fill it, one entry each, whatever the replies hold: with more of them the one that
	// was not asked for the longest time is forgotten. It is asked again, and its next failure is
	// a first one.
	failureCacheSize = 1000

	// firstRefusal is the time for which a query is refused when it goes to the cache of
	// validation failures for the first time: the least that a failure is cached for (RFC 9520
	// §3.2). A failure that follows another is refused for longer (see refusalAfter).
	firstRefusal = time.Second

	// failureMemory is the time for which the cache of validation failures keeps a failure after
	// the refusal of its query has ended, so that the next failure of the query counts as one
	// that follows it. It is the longest refusal: a query that fails whenever its refusal is
	// over stays in the cache, and one that nobody asks for leaves it.
	failureMemory = dnssec.BogusTTL
)

// DNSSECResolver is responsible for DNSSEC validation of DNS responses
type DNSSECResolver struct {
	configurable[*config.DNSSEC]
	NextResolver
	typed

	validator *dnssec.Validator
	// upstreams picks the upstream group of a client when there are several; validation
	// results are cached per group
	upstreams *UpstreamTreeResolver
	// failureCache is the cache of validation failures: the questions whose second reply failed
	// validation too, or did not come, and those with a lookup that ended without a reply, each
	// with what its client was told and for how long it is refused (see refused)
	failureCache *expirationcache.ExpirationLRUCache[validationFailure]
}

// NewDNSSECResolver creates a new DNSSEC resolver instance
func NewDNSSECResolver(ctx context.Context, cfg config.DNSSEC, upstream Resolver) (ChainedResolver, error) {
	// Create resolver with config
	r := &DNSSECResolver{
		configurable: withConfig(&cfg),
		typed:        withType("dnssec"),
	}
	// NewUpstreamTreeResolver returns the group resolver itself when only one group exists, so
	// any other upstream means a single view
	r.upstreams, _ = upstream.(*UpstreamTreeResolver)

	// Only initialize validator if DNSSEC is enabled
	if cfg.IsEnabled() {
		// Load trust anchors
		trustAnchors, err := dnssec.NewTrustAnchorStore(cfg.TrustAnchors)
		if err != nil {
			return nil, fmt.Errorf("failed to load trust anchors: %w", err)
		}

		// Create logger
		_, logger := r.log(ctx)

		// Create validator with upstream resolver and config values
		r.validator = dnssec.NewValidator(
			ctx,
			trustAnchors,
			logger,
			upstream,
			cfg.CacheExpirationHours,
			cfg.MaxChainDepth,
			cfg.MaxNSEC3Iterations,
			cfg.MaxUpstreamQueries,
			cfg.ClockSkewToleranceSec,
		)

		r.failureCache = expirationcache.NewCache[validationFailure](ctx, expirationcache.Options{
			CleanupInterval: dnssec.BogusTTL,
			MaxSize:         failureCacheSize,
		})

		logger.Infof("DNSSEC resolver initialized with %d root trust anchor(s)",
			len(trustAnchors.GetRootTrustAnchors()))
	}

	return r, nil
}

// Resolve validates DNSSEC signatures if validation is enabled
func (r *DNSSECResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	// Without validation the resolver changes neither the query nor the answer, so skip
	// the per-request work (matches the disabled-path early-return of other resolvers).
	if !r.cfg.Validate {
		return r.next.Resolve(ctx, request)
	}

	ctx, logger := r.log(ctx)

	// Set the DO (DNSSEC OK) bit. This overwrites what the client
	// asked for, as RFC 4035 §3.2.1 requires of the resolver side; the server undoes it towards the
	// client afterwards (see clientQuery.normalizeResponse in server/client_query.go), so don't
	// make this conditional on the client's DO bit without adapting that.
	// Check if EDNS0 is already present in the request
	if opt := request.Req.IsEdns0(); opt != nil {
		// EDNS0 already exists - just set the DO bit
		opt.SetDo(true)
		// Ensure buffer size is adequate for DNSSEC responses
		if opt.UDPSize() < ednsUDPSize {
			opt.SetUDPSize(ednsUDPSize)
		}
		logger.Debugf("DNSSEC DO bit set for query (existing EDNS0): %s", request.Req.Question[0].Name)
	} else {
		// No EDNS0 present - add it with DO bit
		request.Req.SetEdns0(ednsUDPSize, true)
		logger.Debugf("DNSSEC DO bit set for query (new EDNS0): %s", request.Req.Question[0].Name)
	}

	q := new(askedQuery)

	if r.validator != nil && len(request.Req.Question) > 0 {
		q.view = r.upstreamGroup(logger, request)
		q.subnet = util.GetEdns0Option[*dns.EDNS0_SUBNET](request.Req)
	}

	return r.answer(ctx, logger, request, q)
}

// askedQuery is a query of a client as this resolver keeps what validation finds for it. view is
// the upstream group of the client: its clients share what is kept. subnet is the client subnet
// option that the query has when it comes to this resolver, if it has one: the one part of the
// message that a resolver below sets anew or removes. Both are those of the second ask too. key
// names the query in the cache of validation failures, once something needs it (see failureKey),
// and last is the failure that the cache held for the query when it was last asked, if it held
// one (see refused).
type askedQuery struct {
	view   string
	subnet *dns.EDNS0_SUBNET
	key    string
	last   *validationFailure
}

// failureKey returns what names q, the query of request, in the cache of validation failures
// (see failureCacheKey). The key is formed when it is first asked for, which is when the cache has
// an entry that the query may match, or when its failure is kept: a query whose reply validates
// while the cache is empty costs no copy of its message and no digest.
func (q *askedQuery) failureKey(request *model.Request) string {
	if q.key == "" {
		q.key = failureCacheKey(request, q.view, q.subnet)
	}

	return q.key
}

// answer returns what the client gets for request, the query q: the reply of the next resolver
// as its validation leaves it. A reply that fails validation is asked for once more before the
// client gets SERVFAIL (see askAgain), and what validation says of the second reply stands,
// whatever that is. A query that the cache of validation failures holds is refused for a while
// without being asked (see refused).
func (r *DNSSECResolver) answer(
	ctx context.Context, logger *logrus.Entry, request *model.Request, q *askedQuery,
) (*model.Response, error) {
	validates := r.validator != nil && len(request.Req.Question) > 0

	if validates {
		if failure := r.refused(request, q); failure != nil {
			logger.Debugf("DNSSEC validation failure cached for %s - returning SERVFAIL without asking: %s",
				request.Req.Question[0].Name, failure.reason)

			return failure.response(request), nil
		}
	}

	// Get response from next resolver (upstream)
	response, err := r.next.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}

	// Validate DNSSEC if the validator is available
	if validates {
		if reason := skipValidationReason(request, response); reason != "" {
			response.Res.AuthenticatedData = false
			logger.Debugf("skipping DNSSEC validation for %s: %s", reason, request.Req.Question[0].Name)

			return response, nil
		}

		// Preserve the originating client's identity so DS/DNSKEY sub-queries issued
		// during validation resolve from the same upstream view as the answer.
		validationCtx := dnssec.WithClientContext(ctx, request.ClientIP, request.ClientNames,
			request.RequestClientID, q.view)

		// The first reply to a question is asked for once more if it fails validation (see failed)
		if !request.AskedAgain {
			validationCtx = dnssec.FirstAsk(validationCtx)
		}

		verdict := r.validator.Validate(validationCtx, response.Res, request.Req.Question[0])
		result := verdict.Result

		logger.Debugf("DNSSEC validation result for %s: %s",
			request.Req.Question[0].Name, result.String())

		switch result {
		case dnssec.ValidationResultBogus:
			return r.failed(validationCtx, logger, request, q, verdict)

		case dnssec.ValidationResultSecure:
			r.validated(q)

			// Valid DNSSEC - set AD flag. The server clears it again for clients that asked for
			// neither DO nor AD, per RFC 6840 §5.8 (see clientQuery.normalizeResponse).
			markAuthentic(response.Res, verdict.Lifetimes)
			logger.Debugf("DNSSEC validation succeeded for %s - AD flag set",
				request.Req.Question[0].Name)

		case dnssec.ValidationResultInsecure, dnssec.ValidationResultIndeterminate:
			r.validated(q)

			// No DNSSEC, or no trust anchor above the name - clear AD flag
			response.Res.AuthenticatedData = false
			logger.Debugf("DNSSEC validation result %s for %s - AD flag cleared",
				result.String(), request.Req.Question[0].Name)
		}
	}

	return response, nil
}

// failureCacheKey returns what names the query of request in the cache of validation failures, for
// the clients of the upstream group view: the SHA-256 digest of the message as this resolver
// passes it on, every octet of it but the ID, with the query name in canonical form. The upstream
// gets the message of the client, and a query with RD clear, in another class or with another
// EDNS version or option gets another reply than the query that a client sends ordinarily for
// that name and type. So a failure is kept for the queries that go to the upstream in the form of
// the one that failed, and for no other: RFC 4035 §4.7 keeps it by <QNAME, QTYPE, QCLASS> and
// lets the cache be no means to deny service, which the rest of the message is part of the key
// for. A digest makes an entry as large for a message of 64 KiB as for one of 30 octets, so the
// entries of the cache bound its memory (RFC 9520 §3.2).
//
// The client subnet option is the part of the message that a resolver below sets anew or removes
// (see ECSResolver). The digest takes it as subnet, the option that the query came with, and the
// message without one, so the key of a query is the same before and after the query went down.
// What that resolver adds from the address of the client is no part of the key. The key is empty
// for a message that cannot be packed: the cache neither answers nor keeps its query.
func failureCacheKey(request *model.Request, view string, subnet *dns.EDNS0_SUBNET) string {
	query := request.Req.Copy()
	query.Id = 0

	for i := range query.Question {
		query.Question[i].Name = dns.CanonicalName(query.Question[i].Name)
	}

	util.RemoveEdns0OptionKeepRecord[*dns.EDNS0_SUBNET](query)

	packed, err := query.Pack()
	if err != nil {
		return ""
	}

	named := append([]byte(view+"\x00"), packed...)
	if subnet != nil {
		named = fmt.Appendf(named, "\x00%d %d %d %s",
			subnet.Family, subnet.SourceNetmask, subnet.SourceScope, subnet.Address)
	}

	digest := sha256.Sum256(named)

	return string(digest[:])
}

// failed returns what the client gets for request, the query q, when verdict says that the reply
// to it failed validation. ctx is the context that the reply was validated in. A first reply is
// asked for once more, and what its validation leaves of the second reply is what the client gets
// (see askAgain). Otherwise the client gets the SERVFAIL that tells of the failure: when the
// reply is the second, and when no second reply comes. The query has then failed twice, and goes
// to the cache of validation failures, which refuses it for the time that refusalAfter gives and
// remembers the failure for failureMemory beyond that (see refused).
//
// A validation that ran out of a budget says how much work its reply asked for, and nothing that
// is kept (see dnssec.Verdict): its reply is not asked for again, as a second one would not have
// more of the budget, and its query does not go to the cache, whichever reply it was.
//
// A reply is not asked for again either if a DS or DNSKEY lookup of its validation ended without
// a reply (see dnssec.Verdict), whatever the verdict rests on: the second ask would make that
// lookup again and wait for it again. The upstream resolver made its tries for it (RFC 9520 §3.1:
// a resolver "MUST NOT retry a given query to a server address over a given DNS transport more
// than twice"), so the client gets its SERVFAIL after one wait for them. A lookup whose two tries
// both got a reply that does not answer it is no such lookup: the reply is asked for again.
//
// The query of such a validation goes to the cache as one that failed twice does. The threshold
// of two (RFC 4035 §4.7) is for replies that are asked for again. A validation that a timeout or
// an unreachable server stopped is a resolution failure (RFC 9520 §2.3), and "Resolvers MUST
// cache resolution failures for at least 1 second" (RFC 9520 §3.2): it is kept from the first.
func (r *DNSSECResolver) failed(
	ctx context.Context, logger *logrus.Entry, request *model.Request, q *askedQuery, verdict dnssec.Verdict,
) (*model.Response, error) {
	name := request.Req.Question[0].Name
	failure := &validationFailure{code: verdict.EDE, reason: "DNSSEC validation failed: " + verdict.Text}

	if !request.AskedAgain && !verdict.RanOut && !verdict.NoReply {
		logger.Debugf("DNSSEC validation failed for %s - asking again: %s", name, verdict.Text)

		again, err := r.askAgain(ctx, logger, request, q)
		if err == nil {
			return again, nil
		}

		logger.Debugf("No second reply for %s: %v", name, err)
	}

	if !verdict.RanOut {
		if key := q.failureKey(request); key != "" {
			failure.refused = refusalAfter(q.last)
			r.failureCache.Put(key, failure, failure.refused+failureMemory)
		}
	}

	// Invalid DNSSEC, or validation that could not be completed - return SERVFAIL
	logger.Warnf("DNSSEC validation failed for %s - returning SERVFAIL: %s", name, verdict.Text)

	return failure.response(request), nil
}

// validationFailure is what a client is told of a reply that failed validation: the INFO-CODE and
// the text of the extended DNS error on its SERVFAIL (see createServFailResponseDNSSEC). In the
// cache of validation failures it also says for how long its query is refused (see refusalAfter).
type validationFailure struct {
	code    uint16
	reason  string
	refused time.Duration
}

// response returns the SERVFAIL that tells the client of request of the failure
func (f *validationFailure) response(request *model.Request) *model.Response {
	return createServFailResponseDNSSEC(request, f.code, f.reason)
}

// refused returns the failure that the query q is refused for, and nil if the cache of validation
// failures refuses it for none. Such a query is answered with that failure, and nothing is asked
// or validated for it. The cache knows a query by its whole message (see failureCacheKey), and a
// query needs its key only while the cache holds an entry.
//
// A failure is cached for the time of its refusal (see refusalAfter): that is the cached failure
// of RFC 9520 §3.2 below, and nothing is sent for its query until that time is over. The entry
// stays for failureMemory after it, only so that the next failure counts as one that follows. So
// a query is refused while more than failureMemory is left of its entry, and asked as any other
// after that. q.last is the entry that the cache holds for it now (see failed and validated).
//
// RFC 9520 §3.4, which updates RFC 4035 §4.7: "security-aware resolvers MUST cache DNSSEC
// validation failures, with some restrictions". RFC 9520 §3.2: "When an incoming query matches a
// cached resolution failure, the resolver MUST NOT send any corresponding outgoing queries until
// after the cache entries expire." The restrictions are those of RFC 4035 §4.7:
//   - A resolver "SHOULD only answer from the BAD cache after the number of times that responses
//     to queries for that particular <QNAME, QTYPE, QCLASS> have failed to validate exceeds a
//     threshold value". Here that is two: the first reply and the one that is asked for again
//     (see askAgain). A query whose validation ran out of a budget is not kept, and one with a
//     lookup that ended without a reply is kept from the first (see failed).
//   - "The implementation MUST assign a TTL. This TTL SHOULD be small". It is a second for a
//     first failure and at most dnssec.BogusTTL, a minute, for one that follows others (see
//     refusalAfter): within the 1 second to 5 minutes of RFC 9520 §3.2.
//   - The memory of the cache is limited (RFC 9520 §3.2): see failureCacheSize.
//
// A client that sets CD validates itself and gets the data as it is (see skipValidationReason).
// Its query is another one than that of a client without CD, and no reply to it is validated, so
// nothing is kept for it and nothing refused to it.
func (r *DNSSECResolver) refused(request *model.Request, q *askedQuery) *validationFailure {
	q.last = nil

	if r.failureCache.TotalCount() == 0 {
		return nil
	}

	key := q.failureKey(request)
	if key == "" {
		return nil
	}

	last, left := r.failureCache.Get(key)
	if left <= 0 {
		return nil
	}

	q.last = last

	if left <= failureMemory {
		return nil
	}

	return last
}

// refusalAfter returns for how long a query is refused that goes to the cache of validation
// failures. last is the failure that the cache held for the query when it was asked, or nil:
//   - A first failure is refused for firstRefusal. "Many validation errors will be transient"
//     (RFC 4035 §4.7), and a failure that passes costs the clients of its query a second.
//   - A failure that follows another, with no reply to the query that validated in between (see
//     validated), is refused for twice the time of the last one, up to dnssec.BogusTTL: a
//     resolver "SHOULD employ an exponential or linear backoff algorithm to increase the cache
//     duration for persistent resolution failures" (RFC 9520 §3.2).
//
// Queries of several clients that fail at one time found the same in the cache when they were
// asked: they count as one failure, and are refused for the same time.
func refusalAfter(last *validationFailure) time.Duration {
	if last == nil {
		return firstRefusal
	}

	return min(2*last.refused, dnssec.BogusTTL)
}

// validated ends the row of failures of q, a query with a reply that validation did not refuse:
// its next failure is a first one (see refusalAfter). The cache is touched only if it held a
// failure of the query when the query was asked.
func (r *DNSSECResolver) validated(q *askedQuery) {
	if q.last != nil {
		r.failureCache.Remove(q.key)
	}
}

// askAgain asks the question of request once more and returns what the client gets for the second
// reply (see answer). ctx is the context that the first reply was validated in.
//
// "Many validation errors will be transient" (RFC 4035 §4.7): a reply that fails validation says
// that the reply is bad, not that the name is. A resolver may leave out a part of what a zone
// sent in one reply and send it whole in the next. For a denial of existence the second ask is
// required (RFC 4035 §5.4): "If the complete set of necessary NSEC RRsets is not present in a
// response (perhaps due to message truncation), then a security-aware resolver MUST resend the
// query", and it "MUST bound the work it puts into answering any particular query". So the
// upstream is asked once more, and no more than that, and a question whose replies fail twice
// goes to the cache of validation failures (see refused). Unbound asks again up to five times,
// past its cache: it prefers another server to the one that sent the reply, and behind a single
// forwarder asks that one again (val-max-restart, val_blacklist). It keeps a result that stays
// bad for a minute (val-bogus-ttl).
//   - The request says that it is asked again, so the cache below does not answer it with the
//     reply that it holds, the one that failed, and no third ask follows.
//   - The second reply is validated on its own, within the budget of the first validation: one
//     client query has one budget (see dnssec.Again). The one more ask and the one budget are
//     the bound of the work.
func (r *DNSSECResolver) askAgain(
	ctx context.Context, logger *logrus.Entry, request *model.Request, q *askedQuery,
) (*model.Response, error) {
	again := *request
	again.AskedAgain = true

	return r.answer(dnssec.Again(ctx), logger, &again, q)
}

// markAuthentic sets the AD flag of msg, a reply that validation found Secure, removes from it
// the records that the flag does not cover (RFC 4035 §3.2.3) and leaves no RRset of it a TTL
// beyond lifetimes, the time for which validation found each authentic (RFC 4035 §5.3.3).
// Nothing else changes a reply because of its validation. The TTLs are those that the client
// gets: the cache below this resolver holds a reply for the time of its own configuration, and
// every reply that it serves is validated again.
func markAuthentic(msg *dns.Msg, lifetimes dnssec.Lifetimes) {
	msg.AuthenticatedData = true

	// The RRSIG records that cover no RRset of their section: validation reads an RRSIG with the
	// RRset that it covers, so nothing vouches for these
	msg.Answer = slices.DeleteFunc(slices.Clone(msg.Answer), dnssec.CoversNoRRset(msg.Answer))
	msg.Ns = slices.DeleteFunc(slices.Clone(msg.Ns), dnssec.CoversNoRRset(msg.Ns))

	// The NS RRsets without RRSIG, which validation leaves out of the status of a reply
	msg.Ns = dnssec.ValidatedAuthority(msg)

	msg.Answer, msg.Ns = lifetimes.Bound(msg.Answer), lifetimes.Bound(msg.Ns)

	// The additional section, which nothing validates, but for the OPT record, which is no data
	// of a zone
	msg.Extra = slices.DeleteFunc(slices.Clone(msg.Extra), func(rr dns.RR) bool {
		return rr.Header().Rrtype != dns.TypeOPT
	})
}

// skipValidationReason returns why a response is passed on without validation (with AD cleared,
// since it wasn't authenticated), or "" if it must be validated.
func skipValidationReason(request *model.Request, response *model.Response) string {
	if response == nil || response.Res == nil {
		return ""
	}

	// Only public-upstream answers carry a chain of trust in the public DNS hierarchy and
	// form the GHSA-x845 attack surface, so validate exactly those: RESOLVED, plus cached
	// upstream answers re-served as CACHED (re-validated on every hit). Every other response
	// type that can reach this resolver from below is trusted-local or synthesized -
	// conditional-upstream private/split-horizon zones (CONDITIONAL), special-use names like
	// localhost (SPECIAL), DNS64-synthesized AAAA (SYNTHESIZED). Those are inherently unsigned
	// with no public chain of trust, so the post-GHSA-x845 handling would classify them bogus
	// - the whole namespace sits under the default root trust anchor - and turn every such
	// lookup into SERVFAIL (#2126). Mirror the rebinding resolver's response-type whitelist
	// and skip validation for them, clearing AD since we have not authenticated them. The
	// RType is assigned by blocky's own resolvers, never by the (attacker-controlled) upstream
	// answer, so a poisoned public answer cannot mislabel itself out of validation.
	if response.RType != model.ResponseTypeRESOLVED && response.RType != model.ResponseTypeCACHED {
		return fmt.Sprintf("trusted-local/synthesized response (%s)", response.RType)
	}

	// A client that sets CD (Checking Disabled) does its own validation and asks for the data as
	// is, so it gets the data even if Blocky's validation would reject it (RFC 4035 §3.2.2,
	// RFC 6840 §5.9) - otherwise a validating stub couldn't even fetch the records it needs to
	// validate. The CD bit is forwarded upstream with the request. Clients without CD still
	// never get such data: the cache below doesn't store positive answers with CD set, and
	// whatever it does serve them (e.g. a negative answer) is re-validated as CACHED.
	if request.Req.CheckingDisabled {
		return "query with CD bit set"
	}

	// RRSIG records have no RRSIG of their own, so nothing can validate the answer to a query for
	// them: not the RRSIG records of the query name, and not those of the name that its CNAME
	// leads to. A reply that answers such a query is passed on whatever its answer section holds,
	// as Unbound does (needs_validation). One without answer is a denial, and is validated.
	if answersRRSIGQuestion(request.Req.Question[0], response.Res) {
		return "answer to a query for RRSIG records"
	}

	return ""
}

// answersRRSIGQuestion reports whether response answers question, a query for RRSIG records: it
// reports no error, and its answer section holds records
func answersRRSIGQuestion(question dns.Question, response *dns.Msg) bool {
	return question.Qtype == dns.TypeRRSIG && response.Rcode == dns.RcodeSuccess && len(response.Answer) > 0
}

// upstreamGroup returns the upstream group that answers the DNSSEC sub-queries of a request
func (r *DNSSECResolver) upstreamGroup(logger *logrus.Entry, request *model.Request) string {
	if r.upstreams == nil {
		return ""
	}

	return r.upstreams.upstreamGroupByClient(logger, request)
}

// createServFailResponseDNSSEC creates a SERVFAIL response for a DNSSEC validation failure,
// with the extended DNS error (RFC 8914) that says why validation failed: code is its INFO-CODE
// and reason its text, which names the records that failed.
//
// The response type is BOGUS, not BLOCKED: a validation failure is a resolution error,
// not a query blocked to protect the client, so it must not be counted as a block in the
// statistics or listed among the top blocked domains. EdeResolver, which sits above this
// resolver and sets the EDE option from the response type, leaves the one set below in place.
func createServFailResponseDNSSEC(request *model.Request, code uint16, reason string) *model.Response {
	modelResp := model.NewResponseWithRcode(request, dns.RcodeServerFailure, model.ResponseTypeBOGUS, reason)
	// The metric label has the kind of failure, without the names that the reason holds
	modelResp.ReasonLabel = "DNSSEC validation failed: " + dns.ExtendedErrorCodeToString[code]

	// Add the EDE (Extended DNS Error) of the validation failure, with the text bounded like
	// that of every other EDE
	edeOption := &dns.EDNS0_EDE{
		InfoCode:  code,
		ExtraText: truncateText(reason, maxEDETextLength),
	}

	// Add EDNS0 OPT record with EDE option
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(ednsUDPSize)
	opt.Option = append(opt.Option, edeOption)
	modelResp.Res.Extra = append(modelResp.Res.Extra, opt)

	return modelResp
}
