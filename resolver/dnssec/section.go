package dnssec

// This file contains the validation of a section of a reply: every RRset of the section gets its
// status once, from the RRSIGs that cover it and the keys of a key source.

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/miekg/dns"
)

// rrsetResult is an RRset of a section with the status that validateSection gives it
type rrsetResult struct {
	owner     string // Owner name (FQDN), as its first record spells it
	rrType    uint16
	rrs       []dns.RR
	status    ValidationResult
	sig       *dns.RRSIG // The RRSIG made for the owner name that verified the RRset, if one did
	expansion *dns.RRSIG // The RRSIG made for a wildcard that did, until its proof (see verifiedBy)
	lifetime  uint32     // How long what verified the RRset lets it be authentic (see verifiedLifetime)
	err       error      // Why the status is not Secure, for logs and for a client (see failure)
	tries     int        // The tries at verifying the RRset so far, each of one RRSIG with one key

	// The RRset is one of the zone above its owner name whatever its type (see holder)
	parentSide bool
}

// newRRsetResult returns the result of an RRset that nothing has verified, which is Bogus
func newRRsetResult(rrset []dns.RR) rrsetResult {
	r := rrsetResult{rrs: rrset}
	if len(rrset) > 0 {
		r.owner, r.rrType = dns.Fqdn(rrset[0].Header().Name), rrset[0].Header().Rrtype
	}

	return r
}

// verifiedBy gives r what sig says about it, an RRSIG that verified its records with a validated
// key. An RRSIG made for the owner name of r makes it Secure. One made for a wildcard that the
// owner name matches verifies the RRset of the wildcard under every such name (RFC 4035 §5.3.2),
// so it says nothing about the name that the records carry: r stays Bogus, and only the proof
// that the wildcard answers for its owner name gives it another status (see proveExpansions).
// Either way sig says how long the records are authentic (see verifiedLifetime).
func (r *rrsetResult) verifiedBy(sig *dns.RRSIG) {
	r.lifetime = verifiedLifetime(r.rrs, sig)

	if isWildcardExpansion(r.owner, sig) {
		r.status, r.sig, r.expansion = ValidationResultBogus, nil, sig
		r.err = fmt.Errorf("no proof that the wildcard %s answers for %s",
			wildcardAt(expansionEncloser(r.owner, sig)), r.owner)

		return
	}

	r.status, r.sig, r.expansion, r.err = ValidationResultSecure, sig, nil, nil
}

// refused reports whether r is Bogus and stays so: no proof is left that could give it another
// status (see verifiedBy)
func (r *rrsetResult) refused() bool {
	return r.status == ValidationResultBogus && r.expansion == nil
}

// signer returns the zone whose RRSIG verified r as the RRset of its owner name, in canonical
// form: that zone signed r. It is empty for every other RRset, also for one that a wildcard gave
// its owner name: the zone signed the RRset of the wildcard.
func (r *rrsetResult) signer() string {
	if r.status != ValidationResultSecure || r.sig == nil {
		return ""
	}

	return dns.CanonicalName(r.sig.SignerName)
}

// keySource gives an RRset its status from the RRSIGs that cover it. It knows which keys may
// verify them, and what an RRset is that none of them verifies.
type keySource interface {
	// verify sets the status of r. sigs are the RRSIGs of the section of r that have its owner
	// name and type.
	verify(ctx context.Context, r *rrsetResult, sigs []*dns.RRSIG)
}

// validateSection returns the RRsets of rrs, the records of a section, in the order of the
// section, each with the status that ks gives it. It verifies up to the first RRset that is Bogus
// for good (see refused): the section is Bogus with it, so the RRsets after it stay what an RRset
// is that nothing has verified. An RRSIG without the RRset that it covers is ignored.
func validateSection(ctx context.Context, rrs []dns.RR, ks keySource) []rrsetResult {
	sigs := rrsigsByRRset(rrs)
	rrsets := orderedRRsets(rrs)
	results := make([]rrsetResult, len(rrsets))

	for i, rrset := range rrsets {
		results[i] = newRRsetResult(rrset)
	}

	for i := range results {
		r := &results[i]

		ks.verify(ctx, r, sigs[rrsetKeyOf(r.rrs[0])])

		if r.refused() {
			break
		}
	}

	return results
}

// worstStatus returns the worst of the statuses of results, the RRsets of a section, and Secure
// for a section without RRsets, which holds nothing that could be wrong
func worstStatus(results []rrsetResult) ValidationResult {
	status := ValidationResultSecure
	for _, r := range results {
		status = worst(status, r.status)
	}

	return status
}

// anyRefused reports whether an RRset of results is Bogus for good (see refused)
func anyRefused(results []rrsetResult) bool {
	return slices.ContainsFunc(results, func(r rrsetResult) bool { return r.refused() })
}

// failure returns why r is not Secure as what a client is told of it: the error of r if that
// holds an extendedError, like the lookup that could not be completed, and else that the RRset
// failed validation
func (r *rrsetResult) failure() error {
	if _, told := errors.AsType[*extendedError](r.err); told {
		return r.err
	}

	return &extendedError{
		code:  dns.ExtendedErrorCodeDNSBogus,
		text:  fmt.Sprintf("%s %s failed validation", r.owner, dns.Type(r.rrType)),
		cause: r.err,
	}
}

// failedTries returns errs, why each try at verifying an RRset failed, as one error. It holds the
// extendedError that a client is told only if every try failed for that: an RRSIG that has
// expired beside one that does not verify leaves no RRset whose signatures have expired
// (RFC 8914 §4.8), and a key that nothing here verifies with beside one that does not verify
// leaves no RRset of such keys only (§4.2). Tries that failed for different things are told as
// none of them.
func failedTries(errs []error) error {
	all := errors.Join(errs...)

	first, told := errors.AsType[*extendedError](all)
	if !told {
		return all
	}

	for _, err := range errs {
		if why, also := errors.AsType[*extendedError](err); !also || why.code != first.code {
			return errors.New(all.Error())
		}
	}

	return all
}

// whyBogus returns why the first Bogus RRset of results is Bogus (see failure), and nil if none is
func whyBogus(results []rrsetResult) error {
	for i := range results {
		if results[i].status == ValidationResultBogus {
			return results[i].failure()
		}
	}

	return nil
}

// chainKeys is the key source for a section that may hold RRsets of any zone, like the sections of
// a reply to a client: an RRSIG is verified with the validated DNSKEY RRset of the zone that it
// names, found by walking the chain of trust to that zone. parentSide names the RRset of the
// section, if there is one, that the reply holds as one of the zone above its owner name (see
// answerChain).
type chainKeys struct {
	v          *Validator
	parentSide rrsetKey
}

// validateAnswer defers unsigned synthesized aliases until their source RRsets have
// been validated, independently of wire order. A signed CNAME is verified normally.
func (ks chainKeys) validateAnswer(ctx context.Context, answer []dns.RR, sources map[rrsetKey]rrsetKey) []rrsetResult {
	if len(sources) == 0 {
		return validateSection(ctx, answer, ks)
	}
	sigs := rrsigsByRRset(answer)
	var aliases, ordinary []dns.RR
	for _, rr := range answer {
		key := rrsetKeyOf(rr)
		if _, made := sources[key]; made && len(sigs[key]) == 0 {
			aliases = append(aliases, rr)
		} else {
			ordinary = append(ordinary, rr)
		}
	}
	results := validateSection(ctx, ordinary, ks)
	dnames := make(map[rrsetKey]rrsetResult)
	for _, r := range results {
		if r.rrType == dns.TypeDNAME {
			dnames[rrsetKeyOf(r.rrs[0])] = r
		}
	}
	for _, rr := range aliases {
		r := newRRsetResult([]dns.RR{rr})
		d := dnames[sources[rrsetKeyOf(rr)]]
		switch {
		case ks.v.hasTrustAnchorBelow(d.owner, r.owner):
			r.err = bogus("DNAME at %s is above a closer trust anchor for %s", d.owner, r.owner)
		case d.signer() != "":
			r.status = ValidationResultSecure
			r.lifetime = min(rr.Header().Ttl, d.lifetime)
		case d.status != ValidationResultBogus:
			ks.verify(ctx, &r, nil)
		default:
			r.err = d.err
		}
		results = append(results, r)
	}

	return results
}

// verify implements keySource. The first of sigs that verifies r says what r is (see verifiedBy).
// Without RRSIGs r has the status of unsigned data in the zone that holds it (see holder).
// Otherwise r is Insecure if an RRSIG names a zone below an insecure delegation, and else has the
// worst of the statuses that its RRSIGs leave it with (see verifyWithSigner), or is Bogus if none
// of them names a signer that may sign r. No RRSIG is looked at once none may be tried any more
// (see tryLeft).
func (ks chainKeys) verify(ctx context.Context, r *rrsetResult, sigs []*dns.RRSIG) {
	r.parentSide = rrsetKey{name: dns.CanonicalName(r.owner), rrType: r.rrType} == ks.parentSide

	if len(sigs) == 0 {
		r.status, r.err = ks.v.unsignedDataStatus(ctx, r)

		return
	}

	var (
		insecure bool
		failed   []ValidationResult
		errs     []error
	)

	b := budgetFrom(ctx)

	// RFC 4035 §5.3.1: every RRSIG is tried; RFC 6840 §5.11: those of the strongest algorithms first
	for _, sig := range ks.v.sortRRSIGsByStrength(sigs) {
		if !b.tryLeft(r) {
			break
		}

		if !ks.v.maySign(sig, r) {
			continue
		}

		switch status, err := ks.verifyWithSigner(ctx, r, sig); {
		case err != nil:
			failed, errs = append(failed, status), append(errs, err)
		case status == ValidationResultSecure:
			r.verifiedBy(sig)

			return
		default:
			insecure = true
		}
	}

	switch {
	case insecure:
		r.status, r.err = ValidationResultInsecure, nil
	case len(failed) > 0:
		r.status, r.err = worst(failed[0], failed[1:]...), failedTries(errs)
	}

	ks.logUnverified(r, r.tries, insecure)
}

// logUnverified logs the status of r, which none of its RRSIGs verified. sigs is the number of
// tries that were made for it, each of one RRSIG with one key.
func (ks chainKeys) logUnverified(r *rrsetResult, sigs int, insecure bool) {
	logger := ks.v.logger

	switch {
	case insecure:
		logger.Debugf("RRSIG verified for %s but chain of trust is insecure (no DS in parent) - treating as Insecure",
			r.owner)
	case r.status == ValidationResultIndeterminate:
		// No trust anchor is above a signer (see classifyUndetermined)
		logger.Warnf("No chain of trust for %s (tried %d signatures), last error: %v - "+
			"treating as Indeterminate", r.owner, sigs, r.err)
	default:
		logger.Warnf("All RRSIG verification attempts failed for %s (tried %d signatures), last error: %v",
			r.owner, sigs, r.err)
	}
}

// maySign reports whether the signer that sig names may sign r. The signer is the zone that holds
// the RRset (RFC 4035 §5.3.1): the name whose zone holds r, or a name above it (see holder). For
// a DS RRset, for the CNAME RRset that answers a question for one and for the NSEC record of a
// delegation that name is the one above the owner, so the zone at their owner name signs none of
// them (RFC 4034 §5, RFC 6840 §4.1). A DNSKEY RRset is at a zone apex, and its signer is its
// owner (RFC 4035 §2.2). Names are compared in canonical form (RFC 4034 §6).
//
// Separately, the signer is no zone above a trust anchor that covers that name, whatever the
// status of the signer's zone: of the trust anchors above a name the closest one decides, for
// signed data as for denials (see denialZone). RFC 6840 §5.10 leaves the choice between such
// trust anchors to the validator and suggests accepting any that succeeds (Appendix C.2). This is
// the closest encloser policy of its Appendix C.1, which Unbound follows too.
func (v *Validator) maySign(sig *dns.RRSIG, r *rrsetResult) bool {
	signer, holder := dns.CanonicalName(sig.SignerName), v.holder(r)

	switch {
	case r.rrType == dns.TypeDNSKEY && signer != dns.CanonicalName(r.owner):
		v.logger.Debugf("Skipping RRSIG: DNSKEY signer %s must equal owner %s (RFC 4035 §2.2)", sig.SignerName, r.owner)
	case !validateSignerName(signer, holder):
		v.logger.Debugf("Skipping RRSIG: signer %s is not at or above %s, whose zone holds the RRset of %s "+
			"(RFC 4035 §5.3.1)", sig.SignerName, holder, r.owner)
	case v.hasTrustAnchorBelow(signer, holder):
		v.logger.Debugf("Skipping RRSIG: a trust anchor below signer %s covers %s, and the closest one decides "+
			"(RFC 6840 Appendix C.1)", sig.SignerName, holder)
	default:
		return true
	}

	return false
}

// verifyWithSigner verifies r with sig and the validated DNSKEY RRset of its signer zone, which it
// finds by walking the chain of trust. Without an error sig verifies r (Secure), or r is Insecure:
// the signer zone is below an insecure delegation (NSEC3 Opt-Out, say), so it has no
// authenticated keys and its signatures prove nothing (RFC 4035 §5.2). With an error sig does not
// verify r, and the status is what that leaves r with unless another RRSIG says more: what
// classifyUndetermined says if the walk did not get to the signer, and Bogus for anything else
// (RFC 4035 §5.5), a key that nothing here can verify with included.
func (ks chainKeys) verifyWithSigner(ctx context.Context, r *rrsetResult, sig *dns.RRSIG) (ValidationResult, error) {
	v := ks.v

	// Only keys of the signer's validated DNSKEY RRset may verify the signature: a key from any
	// other DNSKEY response is unauthenticated
	zone := v.signerKeys(ctx, sig.SignerName)

	switch zone.result {
	case ValidationResultSecure:
	case ValidationResultInsecure:
		return ValidationResultInsecure, nil
	case ValidationResultIndeterminate:
		// Without the keys of the signer nothing can be said about the signature
		return v.classifyUndetermined(sig.SignerName, zone.err)
	case ValidationResultBogus:
		return ValidationResultBogus, errors.Join(zone.err, bogus("the chain of trust to %s is bogus", sig.SignerName))
	}

	if _, err := v.verifyRRset(ctx, r, []*dns.RRSIG{sig}, zone.keys); err != nil {
		v.logger.Debugf("RRSIG verification failed for algorithm=%d, keytag=%d: %v (trying next RRSIG if available)",
			sig.Algorithm, sig.KeyTag, err)

		return ValidationResultBogus, err
	}

	v.logger.Debugf("Successfully verified RRset for %s with algorithm=%d, keytag=%d",
		r.owner, sig.Algorithm, sig.KeyTag)

	return ValidationResultSecure, nil
}

// proveExpansions gives every RRset of sections that waits for it the status of the proof that a
// wildcard answers for its owner name (see verifiedBy). A wildcard answers only for a name that
// does not exist and has no closer match (RFC 4035 §5.3.4, RFC 4592 §3.3.1). The zone of the
// wildcard, which made the RRSIG, gives the proof with its NSEC or NSEC3 records among authority,
// the RRsets of the authority section of the reply (see wildcardExpansion).
//
// Without the proof the RRset stays Bogus. With a proof that is Insecure it is Insecure (RFC 5155
// §9.2). No trust anchor below the zone of the wildcard covers it: the RRSIG of a zone above a
// trust anchor verifies nothing that the anchor covers (see maySign).
//
// The wildcard answers for the name for as long as the proof holds, so the RRset is authentic for
// no longer than the records of the proof (RFC 9077 §4.1).
func (v *Validator) proveExpansions(ctx context.Context, authority []rrsetResult, sections ...[]rrsetResult) {
	for _, results := range sections {
		for i := range results {
			r := &results[i]
			if r.expansion == nil {
				continue
			}

			zone, encloser := dns.CanonicalName(r.expansion.SignerName), expansionEncloser(r.owner, r.expansion)
			r.expansion = nil

			denial := v.newDenialSet(ctx, zone, authority, r.owner, r.rrType)

			switch proof := denial.wildcardExpansion(encloser); proof {
			case ValidationResultSecure, ValidationResultInsecure:
				r.status, r.err = proof, nil
				r.lifetime = min(r.lifetime, denial.lifetime)
			case ValidationResultBogus, ValidationResultIndeterminate:
				v.logger.Warnf("No proof that the wildcard %s answers for %s - treating the RRset as Bogus",
					wildcardAt(encloser), r.owner)
			}
		}
	}
}
