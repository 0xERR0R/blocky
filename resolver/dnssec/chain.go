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

	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

// BogusTTL caps how long a Bogus verdict stays cached, like Unbound's val-bogus-ttl, so a single
// bad answer (an empty or unsigned DNSKEY RRset, say) cannot fail a zone for a whole cache period.
// The resolver refuses a question whose replies go on failing validation for at most as long.
const BogusTTL = time.Minute

// zoneStatus is what the chain of trust walk found at a name, as the validation cache holds it:
// the verdict for the zone of that name. keys holds the zone's validated DNSKEY RRset when result
// is Secure: signatures are only ever verified with these keys. noZoneCut says that the name is no
// zone: the Secure zone above it proved that the name is part of it (see handleDSAbsence), and
// the walk goes through the name with the keys of that zone. err says why the walk went no
// further than the name, if it says more than result: which lookup could not be completed
// (result is Indeterminate, see lookup), or what makes the zone Bogus.
//
// lifetime says how long the name is what the walk found, in seconds: as long as the RRsets that
// proved it are authentic (see verifiedLifetime). These are the DS and DNSKEY RRsets of a Secure
// zone, the denial of the DS RRset of an Insecure one, or its DS RRset if that names no key to
// verify with, and the denial or the CNAME RRset that shows a name to be no zone cut. depth is the
// number of zones of the chain of trust from its trust anchor down to a zone.
type zoneStatus struct {
	result    ValidationResult
	keys      []*dns.DNSKEY
	noZoneCut bool
	lifetime  uint32
	depth     uint
	err       error
}

// startsWalk reports whether a walk to a name below may start at the name of the status: at a
// Secure zone, which has the keys for what is below it, or at an Insecure one, whose status the
// names below it share (see walk)
func (s *zoneStatus) startsWalk() bool {
	return !s.noZoneCut && (s.result == ValidationResultSecure || s.result == ValidationResultInsecure)
}

// validationCacheKey scopes a cached validation result to the upstream view of the originating
// client: the upstream group that answers its DS/DNSKEY sub-queries. Per GHSA-x845-2f78-7v36
// finding 3 the cache must NOT be keyed by bare domain name: a status established for one view
// (split-horizon or upstream group) must not be reused for another. Clients of the same group
// share one view. Requests without a client context share the empty scope. A zone has one entry
// however its name is spelt: the key holds the name in canonical form (RFC 4034 §6.2).
func validationCacheKey(ctx context.Context, domain string) string {
	cc, _ := clientContextFrom(ctx)

	return cc.view + "\x00" + dns.CanonicalName(domain)
}

// cachedZoneStatus returns the unexpired cache entry for domain within the originating client's
// view (see validationCacheKey), or nil. A walk records a cache hit for an entry that it uses: it
// may look at one that it cannot use.
func (v *Validator) cachedZoneStatus(ctx context.Context, domain string) *zoneStatus {
	status, ttl := v.validationCache.Get(validationCacheKey(ctx, domain))
	// The cache returns expired entries until its cleanup runs; keys must not outlive their TTL.
	if status == nil || ttl <= 0 {
		return nil
	}

	return status
}

// setCachedZoneStatus stores what the walk found at domain in the cache, scoped to the originating
// client's view (see validationCacheKey), for the cache period at most. An entry expires with the
// lifetime of the status: a zone is Secure or Insecure, and a name is no zone cut, for as long as
// the records that proved it say so (RFC 4035 §5.3.3; RFC 2308 §5 and RFC 9077 §3.4 for a
// denial). A Bogus result expires after BogusTTL.
//
// Indeterminate is never cached. It means "could not determine": a lookup of the walk could not
// be completed (see lookup), in practice a transient failure (timeout/unreachable upstream).
// Persisting it would fail every later answer signed by that zone (Bogus -> SERVFAIL, see
// classifyUndetermined) for the full cache TTL, even after the upstream recovers - turning one
// transient blip into an hour of failures (issue #2120). Leaving it uncached lets the next query
// re-evaluate the zone and establish its real (durable) status.
//
// Nothing is cached either once the validation has run out of budget. What it finds from then on
// comes from the work that its reply asked for, and no other query may get it as the status of a
// zone.
//
// Neither is a Bogus result of the validation of a first reply, after which the question is asked
// once more: the fault may be that of one reply to a lookup, and the validation of the second
// reply walks again and stores what it finds (see FirstAsk).
func (v *Validator) setCachedZoneStatus(ctx context.Context, domain string, status zoneStatus) {
	if status.result == ValidationResultIndeterminate || budgetFrom(ctx).ranOut() ||
		status.result == ValidationResultBogus && asksAgain(ctx) {
		return
	}

	ttl := min(v.cacheExpiration, time.Duration(status.lifetime)*time.Second)
	if status.result == ValidationResultBogus {
		ttl = min(v.cacheExpiration, BogusTTL)
	}

	v.validationCache.Put(validationCacheKey(ctx, domain), &status, ttl)
}

// signerKeys is the walk to the zone that an RRSIG names as its signer, with the keys of a Secure
// zone as the set that RRSIGs are matched with. A validation walks to a signer once, however many
// RRSIGs name it and whatever the walk finds.
func (v *Validator) signerKeys(ctx context.Context, signer string) signerZone {
	return budgetFrom(ctx).signer(dns.CanonicalName(signer), func() signerZone {
		zone := v.walk(ctx, signer, true)

		return signerZone{result: zone.result, keys: newKeySet(ctx, zone.keys), err: zone.err}
	})
}

// walk returns what the chain of trust walk finds for domain: the security status of its zone
// and, when that is Secure, the zone's validated DNSKEY RRset. The walk starts at the closest
// trust anchor at or above domain and validates each zone below it with the validated keys of the
// zone above. It stops at the first zone that is not Secure: the names below an insecure
// delegation are Insecure, whatever they hold (RFC 4035 §5.2). What the walk finds at a name is
// cached, so zones share their ancestors' work and a warm chain needs no upstream query.
//
// Below the trust anchor the walk starts at the deepest name above domain that the cache holds
// as a zone it can start at (see startsWalk). A zone is what the cache holds for it until the
// records that proved it end (see zoneStatus), whatever has become of the entries for the zones
// above it: no lookup is made for those, and none that fails changes what is below. Unbound
// starts at the closest entry of its key cache in the same way.
//
// mustBeZone is set for a zone that an RRSIG names as its signer: a domain that is part of its
// parent zone has no keys of its own and is Bogus. Without it domain is a name that may be part
// of its parent zone, like co.jp inside jp, and the walk returns the status and keys of the zone
// that holds the name's records, which is also the zone whose status data without RRSIG at the
// name has (see unsignedDataStatus).
//
// The status is Indeterminate if no trust anchor is at or above domain, and if a lookup of the
// walk could not be completed. That says nothing about the zone, and what it means for the data
// of a reply is for classifyUndetermined to say.
func (v *Validator) walk(ctx context.Context, domain string, mustBeZone bool) zoneStatus {
	// The walk is made, and its verdict cached, under the canonical form of the name (RFC 4034
	// §6.2): the names that it asks about are those that its cache entries are for
	domain = dns.CanonicalName(domain)

	// Check cache first. A name that is cached as part of its parent zone has the status of that
	// zone, which the walk finds in the cache too.
	if status := v.cachedZoneStatus(ctx, domain); status != nil && !status.noZoneCut {
		v.logger.Debugf("Using cached validation result for %s: %s", domain, status.result.String())
		v.cacheHitMetrics.Inc()

		return *status
	}

	// Split domain into labels
	labels := dns.SplitDomainName(domain)

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

		return zoneStatus{result: ValidationResultIndeterminate}
	}

	for cut := len(zones) - 2; cut > start; cut-- {
		if zone := v.cachedZoneStatus(ctx, zones[cut]); zone != nil && zone.startsWalk() {
			v.cacheHitMetrics.Inc()

			return v.walkDown(ctx, *zone, zones[cut+1:], mustBeZone)
		}
	}

	return v.walkDown(ctx, v.walkLevel(ctx, zones[start], nil), zones[start+1:], mustBeZone)
}

// walkDown takes the walk from zone, a zone that it has the status of, down names, the names
// below that zone down to the name being walked. Each is validated with the keys of the zone that
// the walk is in when it comes to it (see walkLevel). A name that this zone proves to be part of
// it, like co.jp inside jp, leaves the walk in the zone (RFC 4035 §5.2). mustBeZone makes the walk
// Bogus when the last name is such a name. The walk asks nothing below the first zone that is not
// Secure.
func (v *Validator) walkDown(ctx context.Context, zone zoneStatus, names []string, mustBeZone bool) zoneStatus {
	for i, name := range names {
		if zone.result != ValidationResultSecure {
			break
		}

		level := v.walkLevel(ctx, name, &zone)

		switch {
		case !level.noZoneCut:
			zone = level
		case i == len(names)-1 && mustBeZone:
			v.logger.Warnf("%s is not a zone, so it has no keys to sign with", name)

			return zoneStatus{result: ValidationResultBogus}
		}
	}

	if zone.result != ValidationResultSecure {
		// Zones below an insecure, bogus or unresolved zone share its status.
		return zoneStatus{result: zone.result, err: zone.err}
	}

	return zone
}

// walkLevel returns what the walk finds at name: what the cache holds for it, and else what its
// validation finds, which goes to the cache (see setCachedZoneStatus). Without above, name is the
// zone of a trust anchor, validated with the DNSKEY RRset that a key among its trust anchors signs
// (see anchorKeys). Else above is the Secure zone that the walk is in when it comes to name, and
// its keys validate name (see validateDelegation).
//
// The walk asks one DS query for every name that is not in the cache yet, zone cut or not: nothing
// else tells where the zone cuts above a name are. maxChainDepth is the number of zones that a
// chain of trust may have below its trust anchor: a further zone is Bogus, and nothing is cached
// for it. No RFC sets such a limit. Names that are no zone cut are not counted, however many the
// walk passes: the upstream queries of the validation bound them.
func (v *Validator) walkLevel(ctx context.Context, name string, above *zoneStatus) zoneStatus {
	if status := v.cachedZoneStatus(ctx, name); status != nil {
		v.cacheHitMetrics.Inc()

		return *status
	}

	if above == nil {
		level := v.validateZoneKeys(ctx, name, anchorKeys{v: v, anchors: v.trustAnchors.GetTrustAnchors(name)})
		v.setCachedZoneStatus(ctx, name, level)

		return level
	}

	level := v.validateDelegation(ctx, name, above.keys)

	// A zone below the trust anchor is one more zone of the chain. A query that failed leaves
	// open whether name is one.
	if !level.noZoneCut && level.result != ValidationResultIndeterminate {
		if level.depth = above.depth + 1; level.depth > v.maxChainDepth {
			v.logger.Warnf("Chain of trust to %s has more than the maximum chain depth of %d zones, rejecting",
				name, v.maxChainDepth)

			return zoneStatus{result: ValidationResultBogus}
		}
	}

	v.setCachedZoneStatus(ctx, name, level)

	return level
}

// validateDelegation validates one zone with the validated DNSKEY RRset of its parent zone:
// the parent must sign the zone's DS RRset (or the proof that it has none), and a key of the
// zone's DNSKEY RRset that a DS record names must sign that RRset (RFC 4035 §5.2). Both are the
// RRsets that domain owns in the answers to the lookups for them (see lookup and answerRRset).
//
// When the parent zone proves that domain is part of it and no delegation, the result is Secure
// and no zone cut, without keys: parentZoneKeys sign the records at and below domain up to the
// next zone cut, and a later walk comes through domain with those that the zone above then has.
//
// The status has the lifetime of what proved it: the reply to the DS lookup and, for a Secure
// zone, its DNSKEY RRset too.
func (v *Validator) validateDelegation(ctx context.Context, domain string, parentZoneKeys []*dns.DNSKEY) zoneStatus {
	v.logger.Debugf("Validating domain level: %s", domain)

	// Look up the DS records for the child domain from the parent zone
	// Note: The DS query name is the child domain, but the response comes from parent's authority
	dsResponse, err := v.lookup(ctx, domain, dns.TypeDS)
	if err != nil {
		v.logger.Warnf("Failed to query DS for %s: %v", domain, err)

		return zoneStatus{result: ValidationResultIndeterminate, err: err}
	}

	parent := parentKeys{v: v, keys: newKeySet(ctx, parentZoneKeys)}

	dsRecords, level := parent.dsRRset(ctx, domain, dsResponse)
	switch {
	case level.noZoneCut:
		v.logger.Debugf("%s is part of its parent zone, not a zone cut", domain)

		return level
	case level.result != ValidationResultSecure:
		return level
	}

	zone := v.validateZoneKeys(ctx, domain, delegationKeys{v: v, ds: dsRecords})
	if zone.result != ValidationResultSecure {
		// Without the keys of the zone, the DS RRset alone says what the zone is (see delegationKeys)
		zone.lifetime = level.lifetime

		return zone
	}

	// The zone is Secure for as long as its DS RRset and its DNSKEY RRset both are authentic
	zone.lifetime = min(zone.lifetime, level.lifetime)

	return zone
}

// validateZoneKeys returns the status of zone from its DNSKEY RRset, which it looks up, with the
// keys of the zone and the lifetime of the RRset if that is Secure. ks is the key source for the
// RRset and knows what leads to the zone: the DS RRset of its delegation, or its trust anchors. An
// RRSIG authenticates an RRset as a whole, so the keys of the zone are the records of the RRset
// that ks verifies, all of them and no others (RFC 4035 §5).
func (v *Validator) validateZoneKeys(ctx context.Context, zone string, ks keySource) zoneStatus {
	r, err := v.dnskeyRRset(ctx, zone, ks)

	switch {
	case err != nil:
		// The lookup could not be completed: nothing to keep for the zone (issue #2120)
		v.logger.Warnf("Failed to get DNSKEY for %s: %v", zone, err)

		return zoneStatus{result: ValidationResultIndeterminate, err: err}
	case r.status == ValidationResultSecure:
		v.logger.Debugf("Verified DNSKEY RRset of %s with the RRSIG of key %d", zone, r.sig.KeyTag)

		return zoneStatus{result: ValidationResultSecure, keys: dnskeysOf(r), lifetime: r.lifetime}
	case r.status == ValidationResultInsecure:
		v.logger.Debugf("DS RRset of %s names only keys that cannot be verified with - treating zone as Insecure", zone)
	default:
		v.logger.Warnf("Failed to verify DNSKEY RRset for %s: %v", zone, r.err)

		return zoneStatus{result: r.status, err: r.err}
	}

	return zoneStatus{result: r.status}
}

// dnskeysOf returns the records of r, a DNSKEY RRset, as keys
func dnskeysOf(r *rrsetResult) []*dns.DNSKEY {
	return util.ExtractRecordsFromSlice[*dns.DNSKEY](r.rrs)
}

// parentKeys is the key source for the reply to a DS query: keys is the validated DNSKEY RRset of
// the zone that answers it, the parent of the name asked for. An RRset that none of these keys
// verifies is Bogus, and so is one that only an RRSIG made for a wildcard verifies: no proof
// follows for an RRset of such a reply (see verifiedBy).
type parentKeys struct {
	v    *Validator
	keys keySet
}

// verify implements keySource (see verifyWith)
func (ks parentKeys) verify(ctx context.Context, r *rrsetResult, sigs []*dns.RRSIG) {
	ks.v.verifyWith(ctx, r, sigs, ks.keys)
}

// delegationKeys is the key source for the DNSKEY RRset of a zone below a secure delegation: the
// keys of the RRset that ds names, the DS RRset of the zone (RFC 4035 §5.2). An RRset that none of
// them verifies is Bogus, or Insecure if ds names only keys that nothing here verifies with (see
// onlyUnsupportedKSKs).
type delegationKeys struct {
	v  *Validator
	ds []*dns.DS
}

// verify implements keySource
func (ks delegationKeys) verify(ctx context.Context, r *rrsetResult, sigs []*dns.RRSIG) {
	ksks, allNamed, err := ks.v.keysNamedByDS(dnskeysOf(r), ks.ds, r.owner)
	if err != nil {
		r.err = err

		return
	}

	if !ks.v.verifyWith(ctx, r, sigs, newKeySet(ctx, ksks)) && onlyUnsupportedKSKs(ksks, allNamed) {
		r.status = ValidationResultInsecure
	}
}

// anchorKeys is the key source for the DNSKEY RRset of a zone that has trust anchors: the keys of
// the RRset that are among anchors. An RRset that none of them verifies is Bogus, also one that
// holds no other key: the RRSIG of an anchored key is what says that these records are the DNSKEY
// RRset of the zone (RFC 4035 §5).
type anchorKeys struct {
	v       *Validator
	anchors []*TrustAnchor
}

// verify implements keySource
func (ks anchorKeys) verify(ctx context.Context, r *rrsetResult, sigs []*dns.RRSIG) {
	var anchored []*dns.DNSKEY

	for _, key := range dnskeysOf(r) {
		// Trust anchors are DNSKEY records - validate by matching key content
		if slices.ContainsFunc(ks.anchors, func(anchor *TrustAnchor) bool {
			return key.PublicKey == anchor.Key.PublicKey &&
				key.Algorithm == anchor.Key.Algorithm &&
				key.Flags == anchor.Key.Flags
		}) {
			anchored = append(anchored, key)
		}
	}

	if len(anchored) == 0 {
		r.err = errors.New("no DNSKEY matches a trust anchor")

		return
	}

	ks.v.verifyWith(ctx, r, sigs, newKeySet(ctx, anchored))
}

// rrsigLabelsForOwner returns the RRSIG Labels value of a signature made over the literal name
// owner: its label count, with a leading "*" label not counted (RFC 4034 §3.1.3). A smaller Labels
// value marks a wildcard expansion of a shorter name, which proves nothing about owner itself.
func rrsigLabelsForOwner(owner string) int {
	n := dns.CountLabel(owner)
	if strings.HasPrefix(owner, "*.") {
		n--
	}

	return n
}

// onlyUnsupportedKSKs reports whether every key that the DS RRset names is one of ksks, the keys
// that matched it, and is a key that nothing here can verify with (see canVerifyWith). Like a DS
// RRset of unsupported algorithms only, this leaves no supported path to the zone (RFC 4035
// §5.2). A DS record names the key that has its digest (RFC 4034 §5.1.4), and one whose key is
// missing from the DNSKEY reply may name a supported key stripped from it: allNamed says that
// keysNamedByDS found the key of every DS record.
func onlyUnsupportedKSKs(ksks []*dns.DNSKEY, allNamed bool) bool {
	return allNamed && !slices.ContainsFunc(ksks, canVerifyWith)
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

// keysNamedByDS validates DNSKEYs against DS records and returns all validated KSKs: the zone keys
// of keys that a DS record names by key tag, algorithm and digest (RFC 4035 §5.2). allNamed says
// whether the key of every DS record was found. A DS record names one key, and a record that the
// RRset holds twice is one record, so no key is held against a record twice.
func (v *Validator) keysNamedByDS(
	keys []*dns.DNSKEY, dsRecords []*dns.DS, domain string,
) (validKSKs []*dns.DNSKEY, allNamed bool, err error) {
	const maxDNSKEYValidationAttempts = 16 // Caps digest validation attempts (KeyTrap, CVE-2023-50387).

	dsRecords = distinctDS(dsRecords)
	named := make([]bool, len(dsRecords)) // The DS records whose key was found
	validationAttempts := 0

outer:
	for _, key := range keys {
		// Only a zone key verifies the DNSKEY RRset
		if !isZoneKey(key) {
			continue
		}

		kskTag, isKSK := key.KeyTag(), false
		for i, ds := range dsRecords {
			// RFC 4035 §5.2 requires both Key Tag and Algorithm to match
			// This check is cheap so it does not count against our validation budget
			if named[i] || kskTag != ds.KeyTag || key.Algorithm != ds.Algorithm {
				continue
			}

			// Limit the number of key validations to prevent DoS
			if validationAttempts == maxDNSKEYValidationAttempts {
				if len(validKSKs) == 0 {
					return nil, false, fmt.Errorf("exceeded KSK validation budget (%d attempts)", validationAttempts)
				}

				v.logger.Warnf("Exceeded KSK validation budget for domain %s, stopping with %d validated KSKs",
					domain, len(validKSKs))

				break outer
			}
			validationAttempts++

			if v.validateDNSKEY(key, ds) != nil {
				continue
			}

			if named[i] = true; !isKSK {
				v.logger.Debugf("Validated KSK for %s: flags=%d, algorithm=%d, keytag=%d",
					domain, key.Flags, key.Algorithm, kskTag)

				validKSKs, isKSK = append(validKSKs, key), true
			}
		}
	}

	if len(validKSKs) == 0 {
		return nil, false, errors.New("no DNSKEY matches the parent DS RRset")
	}

	return validKSKs, !slices.Contains(named, false), nil
}

// distinctDS returns dsRecords without the records that say what an earlier one says: they name
// the same key by the same digest
func distinctDS(dsRecords []*dns.DS) []*dns.DS {
	type rdata struct {
		keyTag                uint16
		algorithm, digestType uint8
		digest                string
	}

	seen := make(map[rdata]bool, len(dsRecords))
	distinct := make([]*dns.DS, 0, len(dsRecords))

	for _, ds := range dsRecords {
		id := rdata{ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToLower(ds.Digest)}
		if !seen[id] {
			seen[id] = true

			distinct = append(distinct, ds)
		}
	}

	return distinct
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

// dsRRset returns the DS RRset of domain from dsResponse, the reply to the DS query for it: the
// RRset that domain owns in the answer section (see answerRRset), which the keys of ks, the
// validated keys of the parent zone, must verify.
// Per RFC 4035 §5.2: "The DS RRset MUST be signed by the parent zone's DNSKEY"
//
// level is what the reply makes of domain. With the DS RRset it is Secure for the lifetime of
// that RRset: a zone, which the RRset leads to the keys of. A reply without that RRset has no DS
// RRset of domain, whatever DS records it holds, and says what it proves without one (see
// handleDSAbsence).
func (ks parentKeys) dsRRset(
	ctx context.Context, domain string, dsResponse *dns.Msg,
) (ds []*dns.DS, level zoneStatus) {
	r := answerRRset(ctx, dsResponse, domain, dns.TypeDS, ks)

	switch {
	case r == nil:
		// No DS RRset of domain - check for authenticated denial of existence
		return nil, ks.handleDSAbsence(ctx, domain, dsResponse)
	case r.status != ValidationResultSecure:
		ks.v.logger.Warnf("DS RRset for %s is not signed by its parent zone: %v", domain, r.err)

		return nil, zoneStatus{result: ValidationResultBogus}
	}

	ds = util.ExtractRecordsFromSlice[*dns.DS](r.rrs)

	return ds, zoneStatus{result: ValidationResultSecure, lifetime: r.lifetime}
}

// handleDSAbsence handles the case where no DS records are found
// Per RFC 4035 §5.2: DS absent can mean:
// 1. Unsigned delegation (Insecure) - proven by NSEC/NSEC3 signed by the parent zone
// 2. No delegation (no zone cut) - the NSEC/NSEC3 signed by the parent zone show that
// domain is part of that zone, or domain owns a CNAME RRset of that zone (see ownsCNAME). Unbound
// continues its chain walk on the same proofs.
// 3. Missing proof (Bogus) - the reply proves neither. Without NSEC/NSEC3 records it holds a CNAME
// RRset of domain that the keys of ks do not verify for that name, or the walk would not read it
// (see lookup): like a DS RRset that does not verify, that is no answer of the parent zone.
//
// The proof is read from the denial set of the parent zone, the zone that ks has the keys of: the
// zone above a delegation holds its DS RRset, and so gives the denial of it (RFC 4035 §2.4, §5.2).
// What it proves holds for the lifetime of the records that it is read from: the CNAME RRset, or
// the NSEC or NSEC3 records of the set (see denialSet).
func (ks parentKeys) handleDSAbsence(ctx context.Context, domain string, dsResponse *dns.Msg) zoneStatus {
	v := ks.v

	if lifetime, owns := ks.ownsCNAME(ctx, domain, dsResponse); owns {
		return zoneStatus{result: ValidationResultSecure, noZoneCut: true, lifetime: lifetime}
	}

	// Check for NSEC/NSEC3 records proving DS doesn't exist
	if !hasDenialRecords(dsResponse.Ns) {
		v.logger.Warnf("No DS records for %s and no NSEC/NSEC3 proof - treating as Bogus", domain)

		return zoneStatus{result: ValidationResultBogus}
	}

	// A denial proves nothing unless the parent zone signed it, and no name is hashed for an NSEC3
	// record before that (RFC 9276 §3.2)
	denials, err := ks.verifyDenialSignatures(ctx, dsResponse.Ns)
	if err != nil {
		v.logger.Warnf("NSEC/NSEC3 proof of DS absence for %s is not signed by its parent zone: %v", domain, err)

		return zoneStatus{result: ValidationResultBogus}
	}

	denial := v.newDenialSet(ctx, ks.keys.zone(), denials, domain, dns.TypeDS)
	if denial.noZoneCut() {
		return zoneStatus{result: ValidationResultSecure, noZoneCut: true, lifetime: denial.lifetime}
	}

	// Validate NSEC/NSEC3 proof that DS doesn't exist
	validationResult := denial.noDS(dsResponse.Rcode == dns.RcodeNameError)

	if validationResult == ValidationResultSecure || validationResult == ValidationResultInsecure {
		// Authenticated denial of existence OR NSEC3 opt-out - this is an unsigned delegation
		v.logger.Debugf("Validated NSEC/NSEC3 proof that DS doesn't exist for %s - insecure delegation", domain)

		return zoneStatus{result: ValidationResultInsecure, lifetime: denial.lifetime}
	}

	// NSEC/NSEC3 validation failed - could be an attack
	v.logger.Warnf("NSEC/NSEC3 records present but failed to prove DS absence for %s - treating as Bogus", domain)

	return zoneStatus{result: ValidationResultBogus}
}

// ownsCNAME reports whether dsResponse, the reply to the DS query for domain, shows that domain
// owns a CNAME RRset of the parent zone. A name that owns one has no other data (RFC 1034 §3.6.2,
// RFC 2181 §10.1): no NS RRset, so it is no zone cut, and that RRset is the answer to a query for
// any other type. It counts if the keys of ks make it Secure, which only an RRSIG made for domain
// does: one made for a wildcard says nothing about the name that the records carry (see
// verifiedBy). What the reply holds for the target of the CNAME is not read. lifetime says how
// long the RRset is authentic.
func (ks parentKeys) ownsCNAME(
	ctx context.Context, domain string, dsResponse *dns.Msg,
) (lifetime uint32, owns bool) {
	cname := answerRRset(ctx, dsResponse, domain, dns.TypeCNAME, ks)
	if cname == nil || cname.status != ValidationResultSecure {
		return 0, false
	}

	return cname.lifetime, true
}

// verifyDenialSignatures checks that every NSEC and NSEC3 RRset in rrs is signed by one of the
// keys of ks, and returns these RRsets
func (ks parentKeys) verifyDenialSignatures(ctx context.Context, rrs []dns.RR) ([]rrsetResult, error) {
	denials := slices.DeleteFunc(slices.Clone(rrs), func(rr dns.RR) bool {
		_, isSig := rr.(*dns.RRSIG)

		return !isSig && rr.Header().Rrtype != dns.TypeNSEC && rr.Header().Rrtype != dns.TypeNSEC3
	})

	results := validateSection(ctx, denials, ks)
	for _, r := range results {
		if r.status != ValidationResultSecure {
			return nil, fmt.Errorf("%s %s: %w", r.owner, dns.TypeToString[r.rrType], r.err)
		}
	}

	return results, nil
}
