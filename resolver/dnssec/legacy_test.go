//nolint:unparam // the adapters keep the signatures that the specs call, whatever the specs pass
package dnssec

// Adapters for the specs: functions with the signatures that the specs call, over the functions
// that do the work. New specs call those.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

// maxZoneKeyVerifications is the name that the specs have for the tries that an RRset gets
const maxZoneKeyVerifications = maxRRsetVerifications

// legacyContext returns ctx as the context of a validation, with a budget if it has none: the
// specs call the adapters, which verify and hash, outside a validation
func legacyContext(ctx context.Context) context.Context {
	if budgetFrom(ctx) != nil {
		return ctx
	}

	return context.WithValue(ctx, budgetKey{}, new(budget))
}

// getCachedValidation returns the cached verdict for the zone domain. A name that is cached as
// part of its parent zone is no zone and has none.
func (v *Validator) getCachedValidation(ctx context.Context, domain string) (ValidationResult, bool) {
	status := v.cachedZoneStatus(ctx, domain)
	if status == nil || status.noZoneCut {
		return ValidationResultIndeterminate, false
	}

	return status.result, true
}

// setCachedValidation is setCachedZoneStatus for the verdict of a zone. A verdict had no lifetime:
// it was kept for the cache period, and that of a Secure zone for the shortest TTL of its keys.
func (v *Validator) setCachedValidation(
	ctx context.Context, domain string, result ValidationResult, keys ...*dns.DNSKEY,
) {
	lifetime := uint32(v.cacheExpiration / time.Second)
	for _, key := range keys {
		lifetime = min(lifetime, key.Hdr.Ttl)
	}

	v.setCachedZoneStatus(ctx, domain, zoneStatus{result: result, keys: keys, lifetime: lifetime})
}

// validate is Validate told as the status of the reply and the budget of the validation
func (v *Validator) validate(
	ctx context.Context, response *dns.Msg, question dns.Question,
) (ValidationResult, *budget) {
	verdict, b := v.verdict(ctx, response, question)

	return verdict.Result, b
}

// walkChainOfTrust is the walk to a zone that must be one, told as its status and its keys
func (v *Validator) walkChainOfTrust(ctx context.Context, domain string) (ValidationResult, []*dns.DNSKEY) {
	zone := v.walk(ctx, domain, true)

	return zone.result, zone.keys
}

// walkToEnclosingZone is the walk to the zone that holds name, told as its status and its keys
func (v *Validator) walkToEnclosingZone(ctx context.Context, name string) (ValidationResult, []*dns.DNSKEY) {
	zone := v.walk(ctx, name, false)

	return zone.result, zone.keys
}

// verifyDomainAgainstTrustAnchor is validateZoneKeys with the trust anchors of the zone domain as
// the walk calls it, which it does for a zone that has some. Without any it returned Indeterminate.
func (v *Validator) verifyDomainAgainstTrustAnchor(
	ctx context.Context, domain string,
) (ValidationResult, []*dns.DNSKEY) {
	anchors := v.trustAnchors.GetTrustAnchors(domain)
	if len(anchors) == 0 {
		return ValidationResultIndeterminate, nil
	}

	zone := v.validateZoneKeys(ctx, domain, anchorKeys{v: v, anchors: anchors})

	return zone.result, zone.keys
}

// validateDomainLevel is validateDelegation told as three values: for a domain that is no zone
// cut, zoneCut is false and the keys are those of the parent zone
func (v *Validator) validateDomainLevel(
	ctx context.Context, domain string, parentZoneKeys []*dns.DNSKEY,
) (result ValidationResult, keys []*dns.DNSKEY, zoneCut bool) {
	level := v.validateDelegation(ctx, domain, parentZoneKeys)
	if level.noZoneCut {
		return level.result, parentZoneKeys, false
	}

	return level.result, level.keys, true
}

// unsignedStatus is unsignedDataStatus for data of a type that the zone of its owner name holds
func (v *Validator) unsignedStatus(ctx context.Context, owner string) ValidationResult {
	status, _ := v.unsignedDataStatus(ctx, &rrsetResult{owner: owner})

	return status
}

// checkZoneSecurityStatus is unsignedStatus told as the status of a zone: Secure where data without
// RRSIG at domain is Bogus, and else the status of that data
func (v *Validator) checkZoneSecurityStatus(ctx context.Context, domain string) ValidationResult {
	if status := v.unsignedStatus(ctx, domain); status != ValidationResultBogus {
		return status
	}

	return ValidationResultSecure
}

// validateDSRecordSignature verifies the DS RRset of domain as the chain of trust walk does: with
// the validated DNSKEY RRset of the zone that holds parentDomain, the zone that delegates domain
func (v *Validator) validateDSRecordSignature(
	ctx context.Context, _, parentDomain string, dsRRset []dns.RR, dsRRSIGs ...*dns.RRSIG,
) ValidationResult {
	parentResult, parentZoneKeys := v.walkToEnclosingZone(ctx, parentDomain)
	if parentResult != ValidationResultSecure {
		return parentResult
	}

	r := newRRsetResult(dsRRset)
	parentKeys{v: v, keys: newKeySet(ctx, parentZoneKeys)}.verify(ctx, &r, dsRRSIGs)

	return r.status
}

// findMatchingDNSKEY returns the first of keys that may verify an RRSIG of its own zone with the
// given key tag and algorithm
func findMatchingDNSKEY(keys []*dns.DNSKEY, keyTag uint16, algorithm uint8) *dns.DNSKEY {
	set := newKeySet(context.Background(), keys)

	for _, key := range keys {
		sig := &dns.RRSIG{KeyTag: keyTag, Algorithm: algorithm, SignerName: key.Hdr.Name}
		if slices.Contains(set.mayVerify(sig), key) {
			return key
		}
	}

	return nil
}

// findMatchingRRSIGs returns the RRSIGs of sigs that cover the RRset of the given owner name and
// type, which validateSection finds in an index of its section (see rrsigsByRRset)
func findMatchingRRSIGs(sigs []*dns.RRSIG, ownerName string, rrType uint16) []*dns.RRSIG {
	rrs := make([]dns.RR, len(sigs))
	for i, sig := range sigs {
		rrs[i] = sig
	}

	return rrsigsByRRset(rrs)[rrsetKey{name: dns.CanonicalName(ownerName), rrType: rrType}]
}

// verifyRRSIG is checkRRSIG followed, for an rrsig made for a wildcard, by the proof that the
// wildcard answers for the owner name of rrset, read from nsRecords as verified records (see
// legacyDenialSet). It refused a key of another algorithm than that of rrsig, if rrsig has a
// supported one: mayVerify refuses such a key before checkRRSIG is asked.
func (v *Validator) verifyRRSIG(
	rrset []dns.RR, rrsig *dns.RRSIG, key *dns.DNSKEY, nsRecords []dns.RR, _ string,
) error {
	if v.isSupportedAlgorithm(rrsig.Algorithm) && rrsig.Algorithm != key.Algorithm {
		return fmt.Errorf("algorithm mismatch: RRSIG uses %d, DNSKEY uses %d", rrsig.Algorithm, key.Algorithm)
	}

	ctx := legacyContext(context.Background())
	if err := v.checkRRSIG(ctx, rrset, rrsig, key); err != nil || len(rrset) == 0 {
		return err
	}

	return v.validateWildcardExpansion(rrset[0].Header().Name, rrsig, nsRecords, "")
}

// validateSingleRRset is chainKeys.verify for one RRset and the RRSIGs of its section that have
// the owner name domain, followed by the proof for an RRSIG made for a wildcard, as a reply with
// the authority section nsRecords gives it
func (v *Validator) validateSingleRRset(
	ctx context.Context, rrType uint16, rrset []dns.RR, sigs []*dns.RRSIG,
	domain string, nsRecords []dns.RR, _ string,
) ValidationResult {
	ctx = legacyContext(ctx)
	keys := chainKeys{v: v}

	results := []rrsetResult{newRRsetResult(rrset)}
	results[0].rrType = rrType
	keys.verify(ctx, &results[0], findMatchingRRSIGs(sigs, dns.Fqdn(domain), rrType))

	if !results[0].refused() {
		v.proveExpansions(ctx, validateSection(ctx, nsRecords, keys), results)
	}

	return results[0].status
}

// verifyWithKeys is verifyRRset for an RRset that has *left of its tries left
func (v *Validator) verifyWithKeys(
	ctx context.Context, rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, left *int,
) (*dns.RRSIG, error) {
	r := newRRsetResult(rrset)
	r.tries = maxRRsetVerifications - *left

	ctx = legacyContext(ctx)
	sig, err := v.verifyRRset(ctx, &r, sigs, newKeySet(ctx, keys))
	*left = maxRRsetVerifications - r.tries

	return sig, err
}

// verifyWithZoneKeys is parentKeys.verify for an RRset that has *budget of its tries left
func (v *Validator) verifyWithZoneKeys(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, budget *int) error {
	_, err := v.verifyWithKeys(context.Background(), rrset, sigs, keys, budget)

	return err
}

// legacyParentKeys returns parentKeys for the keys that the adapters below take. The budget that
// they take was the tries that the RRsets of one reply shared. No reply has such a number now:
// every RRset has its own tries, and the validation has a budget for all of them.
func (v *Validator) legacyParentKeys(keys []*dns.DNSKEY) parentKeys {
	return parentKeys{v: v, keys: newKeySet(context.Background(), keys)}
}

// provesNoZoneCut reports whether dsResponse, the reply to a DS query for domain, proves that
// domain is part of the zone of keys and no delegation
func (v *Validator) provesNoZoneCut(domain string, keys []*dns.DNSKEY, dsResponse *dns.Msg, _ *int) bool {
	_, level := v.legacyParentKeys(keys).dsRRset(legacyContext(context.Background()), domain, dsResponse)

	return level.noZoneCut
}

// extractAndValidateDSRecords is dsRRset as it was before it looked for the proof that domain is no
// delegation. A reply that held it denied no DS RRset of a delegation, which was Bogus.
func (v *Validator) extractAndValidateDSRecords(
	domain string, keys []*dns.DNSKEY, dsResponse *dns.Msg, _ *int,
) ([]*dns.DS, ValidationResult) {
	ds, level := v.legacyParentKeys(keys).dsRRset(legacyContext(context.Background()), domain, dsResponse)
	if level.noZoneCut {
		return nil, ValidationResultBogus
	}

	return ds, level.result
}

func (v *Validator) verifyDenialSignatures(rrs []dns.RR, keys []*dns.DNSKEY, _ *int) error {
	_, err := v.legacyParentKeys(keys).verifyDenialSignatures(legacyContext(context.Background()), rrs)

	return err
}

// unverified is the key source of an adapter that returns an RRset as a reply holds it: it leaves
// the RRset what nothing has verified
type unverified struct{}

func (unverified) verify(context.Context, *rrsetResult, []*dns.RRSIG) {}

// queryDNSKEY is dnskeyRRset without a key source: it returns the DNSKEY RRset of the zone domain
// as the reply holds it, as records and as keys
func (v *Validator) queryDNSKEY(ctx context.Context, domain string) ([]dns.RR, []*dns.DNSKEY, error) {
	r, err := v.dnskeyRRset(ctx, domain, unverified{})
	if err != nil {
		return nil, nil, err
	}

	return r.rrs, util.ExtractRecordsFromSlice[*dns.DNSKEY](r.rrs), nil
}

// verifyDNSKEYRRset verifies the DNSKEY RRset of the zone domain in answer with validatedKSKs, as
// the key sources for a DNSKEY RRset do with the keys of the RRset that lead to the zone
func (v *Validator) verifyDNSKEYRRset(
	answer []dns.RR, validatedKSKs []*dns.DNSKEY, domain string,
) (*dns.RRSIG, error) {
	ctx := legacyContext(context.Background())

	r := answerRRset(ctx, &dns.Msg{Answer: answer}, domain, dns.TypeDNSKEY, v.legacyParentKeys(validatedKSKs))
	if r == nil {
		return nil, errors.New("no DNSKEY records found in answer")
	}

	return r.sig, r.err
}

// findAndValidateKSKs is keysNamedByDS without what it says about the DS records
func (v *Validator) findAndValidateKSKs(keys []*dns.DNSKEY, dsRecords []*dns.DS, domain string) ([]*dns.DNSKEY, error) {
	ksks, _, err := v.keysNamedByDS(keys, dsRecords, domain)

	return ksks, err
}

func (v *Validator) validateAnyDNSKEY(keys []*dns.DNSKEY, dsRecords []*dns.DS, domain string) bool {
	ksks, err := v.findAndValidateKSKs(keys, dsRecords, domain)

	return err == nil && len(ksks) > 0
}

// validateAnswer, validateNegativeResponse, validateDenialOfExistence and
// validateAuthorityOrAdditional were branches of a dispatch on the shape of a reply: for a reply
// with an answer section, for a name error or a reply without answer, for the authority section
// of such a reply, and for any other reply with an RRSIG in its authority or additional section.
// responseStatus decides every reply, so each of them is the status that responseStatus returns.
func (v *Validator) validateAnswer(ctx context.Context, response *dns.Msg, question dns.Question) ValidationResult {
	return v.responseStatus(legacyContext(ctx), response, question).Result
}

func (v *Validator) validateNegativeResponse(
	ctx context.Context, response *dns.Msg, question dns.Question,
) ValidationResult {
	return v.validateAnswer(ctx, response, question)
}

func (v *Validator) validateDenialOfExistence(
	ctx context.Context, response *dns.Msg, question dns.Question,
) ValidationResult {
	return v.validateAnswer(ctx, response, question)
}

func (v *Validator) validateAuthorityOrAdditional(
	ctx context.Context, response *dns.Msg, question dns.Question,
) ValidationResult {
	return v.validateAnswer(ctx, response, question)
}

// The adapters below are the proofs of denial that took records. They put the records in a denial
// set as the specs mean them: each verified, in the order given.

// legacyDenialSet returns the denial set of records for name and qtype. The proofs took no zone:
// they read NSEC records of any zone, and NSEC3 records as those of the zone of the first. So the
// set is that of the zone of the first NSEC3 record, or of the root, which every name is in (see
// legacyZone).
func legacyDenialSet[T dns.RR](v *Validator, records []T, name string, qtype uint16) *denialSet {
	return legacyZoneDenialSet(v, records, legacyZone(records), name, qtype)
}

// legacyZone returns the zone of the first NSEC3 record of records, and the root without one
func legacyZone[T dns.RR](records []T) string {
	if nsec3 := extractNSEC3Records(legacyRRs(records)); len(nsec3) > 0 {
		return nsec3Zone(nsec3[0])
	}

	return "."
}

// legacyZoneDenialSet returns the denial set of zone for name and qtype as newDenialSet makes it
// from records that zone signed, each with an RRSIG made for its owner name. Some of the old
// proofs took the zone and the hash parameters of the NSEC3 records from their caller and read
// every record that they were given. A set reads the hash parameters from its records and keeps
// the records that may be part of a proof, so the specs give records that say what they mean.
func legacyZoneDenialSet[T dns.RR](v *Validator, records []T, zone, name string, qtype uint16) *denialSet {
	results := make([]rrsetResult, len(records))
	for i, rr := range records {
		results[i] = newRRsetResult([]dns.RR{rr})
		results[i].verifiedBy(&dns.RRSIG{SignerName: zone, Labels: uint8(rrsigLabelsForOwner(results[i].owner))})
	}

	return v.newDenialSet(legacyContext(context.Background()), zone, results, name, qtype)
}

func (v *Validator) validateNSECDenialOfExistence(response *dns.Msg, question dns.Question) ValidationResult {
	nsecRecords := extractNSECRecords(response.Ns)

	switch {
	case len(nsecRecords) == 0:
		return ValidationResultInsecure
	case response.Rcode == dns.RcodeNameError:
		return v.validateNSECNXDOMAIN(nsecRecords, question.Name)
	}

	return v.validateNSECNODATA(nsecRecords, question.Name, question.Qtype)
}

func (v *Validator) validateNSECNXDOMAIN(nsecRecords []*dns.NSEC, qname string) ValidationResult {
	return legacyDenialSet(v, nsecRecords, qname, dns.TypeNone).nsecNameError()
}

func (v *Validator) validateNSECNODATA(nsecRecords []*dns.NSEC, qname string, qtype uint16) ValidationResult {
	return legacyDenialSet(v, nsecRecords, qname, qtype).nsecNoData()
}

// nsecCoversName reports whether nsec covers name, as nsecFind reads a record of the root zone
// (see legacyDenialSet)
func (v *Validator) nsecCoversName(nsec *dns.NSEC, name string) bool {
	found := legacyDenialSet(v, []*dns.NSEC{nsec}, name, dns.TypeNone).atName

	return found.empty || found.absent != nil
}

// canonicalNameCompare is canonicalName.compare for two names that can be on the wire
func canonicalNameCompare(a, b string) int {
	first, _ := canonicalNameOf(a)
	second, _ := canonicalNameOf(b)

	return first.compare(second)
}

func (v *Validator) nsecHasType(nsec *dns.NSEC, qtype uint16) bool {
	return slices.Contains(nsec.TypeBitMap, qtype)
}

func (v *Validator) computeNSEC3Hash(name string, hashAlg uint8, salt string, iterations uint16) (string, error) {
	if hashAlg != dns.SHA1 {
		return "", fmt.Errorf("unsupported NSEC3 hash algorithm: %d", hashAlg)
	}

	return nsec3Hash(name, salt, iterations), nil
}

// validateNSEC3DenialOfExistence is validateDenialOfExistence for the NSEC3 records of a reply
// whose authority section is taken as verified
func (v *Validator) validateNSEC3DenialOfExistence(response *dns.Msg, question dns.Question) ValidationResult {
	records := extractNSEC3Records(response.Ns)
	if !hasDenialRecords(legacyRRs(records)) {
		return ValidationResultInsecure
	}

	d := legacyDenialSet(v, records, question.Name, question.Qtype)
	if response.Rcode == dns.RcodeNameError {
		return d.nameError()
	}

	return d.noData()
}

// validateNSEC3NXDOMAIN is nsec3NameError for the NSEC3 records of the zone zoneName. The hash
// parameters are those of the records (see legacyZoneDenialSet).
func (v *Validator) validateNSEC3NXDOMAIN(nsec3Records []*dns.NSEC3, qname, zoneName string,
	_ uint8, _ string, _ uint16,
) ValidationResult {
	return legacyZoneDenialSet(v, nsec3Records, zoneName, qname, dns.TypeNone).nsec3NameError()
}

// validateNSEC3NODATA is nsec3NoData for the NSEC3 records of the zone zoneName. The hash
// parameters are those of the records (see legacyZoneDenialSet).
func (v *Validator) validateNSEC3NODATA(nsec3Records []*dns.NSEC3, qname string, qtype uint16,
	zoneName string, _ uint8, _ string, _ uint16,
) ValidationResult {
	return legacyZoneDenialSet(v, nsec3Records, zoneName, qname, qtype).nsec3NoData()
}

// checkDirectNSEC3Match is the part of nsec3NoData for a name with an NSEC3 record. Without one
// it returned Indeterminate.
func (v *Validator) checkDirectNSEC3Match(nsec3Records []*dns.NSEC3, qname, qnameHash string,
	qtype uint16,
) ValidationResult {
	d := legacyDenialSet(v, nsec3Records, qname, qtype)
	if rr := d.match(qnameHash); rr != nil {
		return d.nsec3MatchNoData(rr)
	}

	return ValidationResultIndeterminate
}

// checkWildcardNSEC3Match is the part of nsec3NoData for a name without an NSEC3 record, for the
// NSEC3 records of the zone zoneName. The hash parameters are those of the records (see
// legacyZoneDenialSet).
func (v *Validator) checkWildcardNSEC3Match(nsec3Records []*dns.NSEC3, qname string, qtype uint16,
	zoneName string, _ uint8, _ string, _ uint16, _ string,
) ValidationResult {
	d := legacyZoneDenialSet(v, nsec3Records, zoneName, qname, qtype)
	if d.nsec3Err != nil {
		return ValidationResultBogus
	}

	return d.nsec3WildcardNoData()
}

// findClosestEncloser is closestEncloser without the next closer name, for the NSEC3 records of
// the zone zoneName. The hash parameters are those of the records (see legacyZoneDenialSet).
func (v *Validator) findClosestEncloser(qname, zoneName string, nsec3Records []*dns.NSEC3,
	_ uint8, _ string, _ uint16,
) string {
	d := legacyZoneDenialSet(v, nsec3Records, zoneName, qname, dns.TypeNone)
	if d.nsec3Err != nil {
		return ""
	}

	encloser, _ := d.closestEncloser(qname)

	return encloser
}

func (v *Validator) getNextCloser(qname, closestEncloser string) string {
	return nextCloser(qname, closestEncloser)
}

// nsec3Covers is cover without what it says about Opt-Out, for the NSEC3 records of the zone of
// the first (see legacyZone)
func (v *Validator) nsec3Covers(nsec3Records []*dns.NSEC3, hash string) bool {
	zone := legacyZone(nsec3Records)
	covered, _ := legacyZoneDenialSet(v, nsec3Records, zone, zone, dns.TypeNone).cover(hash)

	return covered
}

// nsec3CoversWithOptOut is what cover says about Opt-Out (see nsec3Covers)
func (v *Validator) nsec3CoversWithOptOut(nsec3Records []*dns.NSEC3, hash string) bool {
	zone := legacyZone(nsec3Records)
	_, optOut := legacyZoneDenialSet(v, nsec3Records, zone, zone, dns.TypeNone).cover(hash)

	return optOut
}

// legacyRRs returns records as the records of a section
func legacyRRs[T dns.RR](records []T) []dns.RR {
	rrs := make([]dns.RR, len(records))
	for i, rr := range records {
		rrs[i] = rr
	}

	return rrs
}

// validateWildcardExpansion is the check of the wildcard that rrsig may be made for: that it is in
// the zone of the signer, which checkRRSIG checks, and that it answers for rrsetName, which a
// reply proves after that (see proveExpansions)
func (v *Validator) validateWildcardExpansion(
	rrsetName string, rrsig *dns.RRSIG, nsRecords []dns.RR, qname string,
) error {
	rrsetName = dns.Fqdn(rrsetName)
	if !isWildcardExpansion(rrsetName, rrsig) {
		return nil
	}

	return v.validateWildcardExpansionDetails(rrsetName, dns.Fqdn(rrsig.SignerName), int(rrsig.Labels), nsRecords, qname)
}

func (v *Validator) validateWildcardExpansionDetails(
	rrsetName, signerName string, rrsigLabels int, nsRecords []dns.RR, qname string,
) error {
	if labels := dns.CountLabel(rrsetName); labels < rrsigLabels {
		return fmt.Errorf("invalid wildcard: RRset has %d labels but RRSIG claims %d", labels, rrsigLabels)
	}

	wildcardName := wildcardAt(expansionEncloser(rrsetName, &dns.RRSIG{Labels: uint8(rrsigLabels)}))
	if !dns.IsSubDomain(signerName, wildcardName) {
		return fmt.Errorf("wildcard %s not within signer zone %s", wildcardName, signerName)
	}

	return v.validateWildcardProof(wildcardName, rrsetName, nsRecords, qname)
}

// validateWildcardProof is wildcardExpansion for the wildcard wildcardName, with the NSEC and
// NSEC3 records of nsRecords as verified records (see legacyDenialSet). It returned an error for
// a proof that failed, and had no proof that was Insecure.
func (v *Validator) validateWildcardProof(wildcardName, rrsetName string, nsRecords []dns.RR, _ string) error {
	d := legacyDenialSet(v, nsRecords, rrsetName, dns.TypeNone)
	if d.wildcardExpansion(v.getParentDomain(wildcardName)) != ValidationResultSecure {
		return fmt.Errorf("wildcard validation failed: no proof that %s answers for %s", wildcardName, d.name)
	}

	return nil
}

// validateWildcardNSEC is wildcardExpansion with NSEC records. It took no wildcard: the proof was
// that a record covers qname, which is the proof for the wildcard one label above qname.
func (v *Validator) validateWildcardNSEC(nsecRecords []*dns.NSEC, qname string) error {
	d := legacyDenialSet(v, nsecRecords, qname, dns.TypeNone)
	if d.wildcardExpansion(v.getParentDomain(qname)) != ValidationResultSecure {
		return fmt.Errorf("no NSEC record covers query name %s to prove non-existence", d.name)
	}

	return nil
}

// validateWildcardNSEC3 is wildcardExpansion with NSEC3 records, which failed without any. It took
// no wildcard: the proof was that a record covers the hash of qname, which is the proof for the
// wildcard one label above qname. And it returned why the parameters of the records prove nothing.
func (v *Validator) validateWildcardNSEC3(nsec3Records []*dns.NSEC3, qname string) error {
	if len(nsec3Records) == 0 {
		return errors.New("no NSEC3 records available")
	}

	d := legacyDenialSet(v, nsec3Records, qname, dns.TypeNone)
	if d.nsec3Err != nil {
		return d.nsec3Err
	}

	if d.wildcardExpansion(v.getParentDomain(qname)) != ValidationResultSecure {
		return fmt.Errorf("no NSEC3 record covers query name %s to prove non-existence", d.name)
	}

	return nil
}

// validateDSAbsenceProof is noDS with the NSEC records of the reply if hasNSEC says that it has
// any, without which it returned Bogus, and else with its NSEC3 records
func (v *Validator) validateDSAbsenceProof(domain string, dsResponse *dns.Msg, hasNSEC bool) ValidationResult {
	nameError := dsResponse.Rcode == dns.RcodeNameError
	if !hasNSEC {
		return legacyDenialSet(v, extractNSEC3Records(dsResponse.Ns), domain, dns.TypeDS).noDS(nameError)
	}

	d := legacyDenialSet(v, extractNSECRecords(dsResponse.Ns), domain, dns.TypeDS)
	if len(d.nsec) == 0 {
		return ValidationResultBogus
	}

	return d.noDS(nameError)
}
