package dnssec

// This file contains RRset and RRSIG signature validation logic per RFC 4035.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

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

	// DNSKEY validation constants
	dnskeyProtocolValue = 3  // Required protocol field value
	publicKeyPrefixLen  = 40 // Length of public key prefix for logging
	bitsPerByte         = 8  // Number of bits in a byte
)

var errRRSIGVerificationFailed = errors.New("signature verification failed")

// getAlgorithmStrength returns a strength score for a DNSSEC algorithm
// Higher scores indicate stronger algorithms (used to prevent downgrade attacks)
func (v *Validator) getAlgorithmStrength(alg uint8) int {
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
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1: // Algorithm 5, 7 - deprecated/weak
		return algorithmStrengthRSASHA1
	default:
		return algorithmStrengthUnsupported
	}
}

// selectBestRRSIG selects the RRSIG with the strongest algorithm from a list
// This prevents algorithm downgrade attacks per RFC 6840 §5.11
func (v *Validator) selectBestRRSIG(rrsigs []*dns.RRSIG) *dns.RRSIG {
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

// sortRRSIGsByStrength sorts RRSIGs by algorithm strength (strongest first)
// Per RFC 4035 §5.3.1: Try all signatures, preferring stronger algorithms
func (v *Validator) sortRRSIGsByStrength(rrsigs []*dns.RRSIG) []*dns.RRSIG {
	if len(rrsigs) <= 1 {
		return rrsigs
	}

	// Create a copy to avoid modifying the original slice. RRSIGs of one strength keep their order.
	sorted := slices.Clone(rrsigs)
	slices.SortStableFunc(sorted, func(a, b *dns.RRSIG) int {
		return v.getAlgorithmStrength(b.Algorithm) - v.getAlgorithmStrength(a.Algorithm)
	})

	return sorted
}

// rrsigsByRRset returns the RRSIGs of rrs, the records of a section, by the RRset that each
// covers, in the order of the section. An RRSIG covers the RRset that has its owner name and the
// type of its Type Covered field (RFC 4035 §5.3.1).
func rrsigsByRRset(rrs []dns.RR) map[rrsetKey][]*dns.RRSIG {
	sigs := make(map[rrsetKey][]*dns.RRSIG)

	for _, rr := range rrs {
		if sig, isSig := rr.(*dns.RRSIG); isSig {
			key := rrsetKey{name: dns.CanonicalName(sig.Hdr.Name), rrType: sig.TypeCovered}
			sigs[key] = append(sigs[key], sig)
		}
	}

	return sigs
}

// validateSignerName validates that the RRSIG signer name is valid for the RRset
// RFC 4035 §5.3.1: The signer name must be equal to or a parent of the RRset owner name
func validateSignerName(signerName, rrsetName string) bool {
	return dns.IsSubDomain(signerName, rrsetName)
}

// isZoneKey reports whether key is a key that RRSIGs are verified with: it has the Zone Key flag
// (RFC 4034 §2.1.1) and the protocol value 3 (RFC 4034 §2.1.2), and it is not revoked (RFC 5011
// §2.1).
func isZoneKey(key *dns.DNSKEY) bool {
	return key.Flags&dns.ZONE != 0 && key.Flags&dns.REVOKE == 0 && key.Protocol == dnskeyProtocolValue
}

// keyID is what an RRSIG names the key that made it by: the zone that owns the key, in canonical
// form (RFC 4034 §6), its key tag and its algorithm (RFC 4035 §5.3.1)
type keyID struct {
	zone      string
	tag       uint16
	algorithm uint8
}

// keySet holds the keys of a DNSKEY RRset that RRSIGs are verified with, each under what an RRSIG
// names it by, so that the keys for an RRSIG are found without looking at the others. Key tags
// are not unique: an RRSIG may name several keys of a set (RFC 4035 §5.3.1).
type keySet map[keyID][]*dns.DNSKEY

// newKeySet returns the key set of keys: those that are zone keys with the protocol value 3 and
// not revoked (RFC 4034 §2.1.1 and §2.1.2, RFC 5011 §2.1: see isZoneKey). The validation of ctx
// computes the key tag of a key once.
func newKeySet(ctx context.Context, keys []*dns.DNSKEY) keySet {
	b, set := budgetFrom(ctx), make(keySet, len(keys))

	for _, key := range keys {
		if isZoneKey(key) {
			id := keyID{zone: dns.CanonicalName(key.Hdr.Name), tag: b.keyTag(key), algorithm: key.Algorithm}
			set[id] = append(set[id], key)
		}
	}

	return set
}

// zone returns the zone that owns the keys of the set, in canonical form: a set holds the keys of
// one DNSKEY RRset. It is empty for a set without keys. That names no zone, and not the root: a
// set without keys verifies no RRset, so nothing is read as a record of its zone.
func (keys keySet) zone() string {
	for id := range keys {
		return id.zone
	}

	return ""
}

// mayVerify returns the keys of the set that may verify sig: those with its key tag and its
// algorithm that the signer which it names owns
func (keys keySet) mayVerify(sig *dns.RRSIG) []*dns.DNSKEY {
	return keys[keyID{zone: dns.CanonicalName(sig.SignerName), tag: sig.KeyTag, algorithm: sig.Algorithm}]
}

// verifyRRset returns the first of sigs, RRSIGs that cover the RRset of r, that verifies it with
// one of keys. Key tags are not unique, so an RRSIG is tried with every key that may verify it
// (RFC 4035 §5.3.1). Each try comes out of the budget of ctx (see spendTry), and without one left
// nothing more is tried.
//
// No RRSIG made for a wildcard is tried for a DS or DNSKEY RRset. A wildcard gives no name a DS
// RRset or keys (RFC 4592 §4.6): a DS RRset is that of the delegation that owns it, with digests
// that cover the owner name of a key (RFC 4034 §5.1.4), and the keys of a zone are the DNSKEY
// RRset at its apex.
func (v *Validator) verifyRRset(
	ctx context.Context, r *rrsetResult, sigs []*dns.RRSIG, keys keySet,
) (*dns.RRSIG, error) {
	var errs []error

	b := budgetFrom(ctx)

	for _, sig := range sigs {
		if (r.rrType == dns.TypeDS || r.rrType == dns.TypeDNSKEY) && isWildcardExpansion(r.owner, sig) {
			errs = append(errs, fmt.Errorf("RRSIG %d was made for a wildcard, which has no such RRset for %s",
				sig.KeyTag, r.owner))

			continue
		}

		for _, key := range keys.mayVerify(sig) {
			if err := b.spendTry(r); err != nil {
				return nil, errors.Join(append(errs, err)...)
			}

			err := v.checkRRSIG(ctx, r.rrs, sig, key)
			if err == nil {
				return sig, nil
			}

			errs = append(errs, err)
		}
	}

	if errs == nil {
		return nil, errors.New("no RRSIG made by a validated key")
	}

	return nil, failedTries(errs)
}

// verifyWith gives r what the first of sigs says that verifies it with one of keys (see verifyRRset
// and verifiedBy), and reports whether one did. Without one r stays what it is.
func (v *Validator) verifyWith(ctx context.Context, r *rrsetResult, sigs []*dns.RRSIG, keys keySet) bool {
	sig, err := v.verifyRRset(ctx, r, sigs, keys)
	if err != nil {
		r.err = err

		return false
	}

	r.verifiedBy(sig)

	return true
}

// verifiedLifetime returns how long rrset is authentic, in seconds, as the RRset that sig, an
// RRSIG that covers it, verified: no longer than the TTL of its records, the TTL of sig, the
// Original TTL field of sig and the time until sig expires (RFC 4035 §5.3.3). Whatever the RRset
// proves holds no longer. It is zero for an RRSIG that has expired and verifies within the clock
// skew tolerance.
func verifiedLifetime(rrset []dns.RR, sig *dns.RRSIG) uint32 {
	untilExpiration := max(int64(sig.Expiration)-time.Now().Unix(), 0)
	lifetime := min(sig.Hdr.Ttl, sig.OrigTtl, uint32(untilExpiration)) //nolint:gosec // below the uint32 expiration

	for _, rr := range rrset {
		lifetime = min(lifetime, rr.Header().Ttl)
	}

	return lifetime
}

// Lifetimes holds how long the RRsets of the answer and authority sections of a reply are
// authentic, in seconds: each for as long as the RRSIG that verified it lets it be (see
// verifiedLifetime), and one that a wildcard answers with no longer than the proof of that (see
// proveExpansions). An RRset that both sections hold has the shorter of its two lifetimes.
type Lifetimes map[rrsetKey]uint32

// newLifetimes returns the lifetimes of the RRsets of sections, sections of verified RRsets
func newLifetimes(sections ...[]rrsetResult) Lifetimes {
	lifetimes := make(Lifetimes)

	for _, results := range sections {
		for i := range results {
			key := rrsetKeyOf(results[i].rrs[0])
			if lifetime, held := lifetimes[key]; !held || results[i].lifetime < lifetime {
				lifetimes[key] = results[i].lifetime
			}
		}
	}

	return lifetimes
}

// Bound returns rrs, the records of the answer or authority section of the reply, with no TTL
// beyond the lifetime of the RRset that the record is part of or, as an RRSIG, covers: the TTL of
// an authenticated RRset and of its RRSIGs is no longer than that (RFC 4035 §5.3.3). A record
// with a longer TTL is returned as a copy, and the reply stays as it is.
func (l Lifetimes) Bound(rrs []dns.RR) []dns.RR {
	bound := slices.Clone(rrs)

	for i, rr := range bound {
		key := rrsetKeyOf(rr)
		if sig, isSig := rr.(*dns.RRSIG); isSig {
			key.rrType = sig.TypeCovered
		}

		if lifetime, verified := l[key]; verified && rr.Header().Ttl > lifetime {
			bound[i] = dns.Copy(rr)
			bound[i].Header().Ttl = lifetime
		}
	}

	return bound
}

// isSupportedAlgorithm checks if the DNSSEC algorithm is supported
// Per RFC 4035 §2.2, validators must treat unsupported algorithms as Insecure
func (v *Validator) isSupportedAlgorithm(alg uint8) bool {
	// Supported algorithms as per RFC 8624 (DNSSEC Algorithm Implementation Status)
	// These are the algorithms supported by the miekg/dns library
	switch alg {
	case dns.RSASHA1, // Algorithm 5 (deprecated but still supported)
		dns.RSASHA1NSEC3SHA1, // Algorithm 7 (same as 5, used with NSEC3)
		dns.RSASHA256,        // Algorithm 8 (recommended)
		dns.RSASHA512,        // Algorithm 10 (recommended)
		dns.ECDSAP256SHA256,  // Algorithm 13 (recommended)
		dns.ECDSAP384SHA384,  // Algorithm 14 (recommended)
		dns.ED25519,          // Algorithm 15 (recommended)
		dns.ED448:            // Algorithm 16 (recommended, RFC 8080)
		return true
	default:
		return false
	}
}

// checkRRSIG verifies the signature of rrsig over rrset with key, a key that may verify it (see
// mayVerify): its algorithm, its Labels field, the zone of its signer if it was made for a
// wildcard, the signature itself, which counts as a verification on the budget of ctx, and then
// its validity period. Whether a wildcard answers for the owner name of rrset is for the caller
// to check (see proveExpansions). A failure that an extended DNS error names is an extendedError
// with its code: an algorithm or a key that nothing here verifies with (RFC 8914 §4.2), and, for
// a signature that verifies, a validity period that has ended or not begun (§4.8, §4.9).
func (v *Validator) checkRRSIG(ctx context.Context, rrset []dns.RR, rrsig *dns.RRSIG, key *dns.DNSKEY) error {
	// Log DNSKEY details including public key prefix for debugging
	pkeyPrefix := key.PublicKey
	if len(pkeyPrefix) > publicKeyPrefixLen {
		pkeyPrefix = pkeyPrefix[:publicKeyPrefixLen]
	}
	v.logger.Debugf(
		"verifyRRSIG: Using DNSKEY flags=%d, protocol=%d, algorithm=%d, "+
			"Header.Name='%s', pubkey_prefix=%s... to verify RRSIG keytag=%d, algorithm=%d, SignerName='%s'",
		key.Flags, key.Protocol, key.Algorithm, key.Header().Name, pkeyPrefix,
		rrsig.KeyTag, rrsig.Algorithm, rrsig.SignerName)

	// Check algorithm support per RFC 4035 §2.2
	// Unsupported algorithms should be treated as Insecure, not Bogus
	if !v.isSupportedAlgorithm(rrsig.Algorithm) {
		return unsupported("unsupported DNSSEC algorithm: %d", rrsig.Algorithm)
	}

	// RFC 4035 §5.3.1: the Labels field counts no more labels than the owner name has, as an RRSIG
	// made for that name counts them (see isWildcardExpansion)
	if len(rrset) > 0 && int(rrsig.Labels) > rrsigLabelsForOwner(rrset[0].Header().Name) {
		return fmt.Errorf("RRSIG counts %d labels, more than its owner name has", rrsig.Labels)
	}

	if err := wildcardInSignerZone(rrset, rrsig); err != nil {
		return fmt.Errorf("wildcard validation failed: %w", err)
	}

	// RFC 4035 §5.3.1: the current time is at or after the inception and at or before the
	// expiration, so no time is within a validity period that ends before it begins. The clock skew
	// tolerance below must not make such a period valid.
	if rrsig.Inception > rrsig.Expiration {
		return fmt.Errorf("signature inception after expiration (inception: %d, expiration: %d)",
			rrsig.Inception, rrsig.Expiration)
	}

	// Capture timestamp once at the start to avoid TOCTOU race condition
	// RFC 4035 §5.3.1: The validator's notion of the current time MUST be
	// greater than or equal to the signature inception time and less than
	// the signature expiration time.
	// RFC 6781 §4.1.2: Validators should account for clock skew in deployment environments.
	// By capturing the timestamp once and using it for all time checks,
	// we ensure consistent time validation even if verification takes time.
	now := uint32(time.Now().Unix()) //nolint:gosec // DNSSEC uses uint32 timestamps per RFC 4034

	// Apply clock skew tolerance (default 3600s = 1 hour, per Unbound/BIND)
	// This allows validation to succeed even if system clock is off by this amount
	tolerance := int64(v.clockSkewToleranceSec) //nolint:gosec // clockSkewToleranceSec is a small configured value
	inceptionWithSkew := int64(rrsig.Inception) - tolerance
	expirationWithSkew := int64(rrsig.Expiration) + tolerance

	// RFC 4035 §5.5: the RRSIG of a key that nothing here verifies with fails like any other
	if !canVerifyWith(key) {
		return unsupported("no support for the RSA exponent of DNSKEY %d", rrsig.KeyTag)
	}

	budgetFrom(ctx).spendVerification()

	// The key decides what verifies the signature (expensive crypto operation). Go's crypto/rsa
	// cannot load exponents above 2^31-1, so miekg/dns reports "dns: bad key" for an RSA/SHA-256
	// or RSA/SHA-512 key that has one (e.g. exponent 2^32+1), and math/big verifies with it
	// (issue #2364).
	var err error
	if rsaKeyNeedsBigMath(key) {
		err = verifyRSAWithBigExponent(rrset, rrsig, key)
	} else {
		err = rrsig.Verify(key, rrset)
	}

	if err != nil {
		v.logFailedVerification(rrset, rrsig)

		return fmt.Errorf("%w: %w", errRRSIGVerificationFailed, err)
	}

	// The validity period comes last. Only a signature that the key made says that its zone let
	// it expire, or published it early: one that does not verify is a failed signature, whatever
	// its dates. Unbound checks in this order too.
	if int64(now) < inceptionWithSkew {
		return extended(dns.ExtendedErrorCodeSignatureNotYetValid,
			"signature not yet valid (inception: %d, now: %d, tolerance: %ds)", rrsig.Inception, now, v.clockSkewToleranceSec)
	}
	if int64(now) > expirationWithSkew {
		return extended(dns.ExtendedErrorCodeSignatureExpired,
			"signature expired (expiration: %d, now: %d, tolerance: %ds)", rrsig.Expiration, now, v.clockSkewToleranceSec)
	}

	return nil
}

// logFailedVerification logs the records and the RRSIG of a verification that failed, for
// debugging. Their text is made only if it is logged.
func (v *Validator) logFailedVerification(rrset []dns.RR, rrsig *dns.RRSIG) {
	if !v.logger.Logger.IsLevelEnabled(logrus.DebugLevel) {
		return
	}

	v.logger.Debugf("Signature verification failed for RRset with %d records:", len(rrset))

	for i, rr := range rrset {
		v.logger.Debugf("  [%d] %s", i, rr.String())
	}

	v.logger.Debugf("  RRSIG: %s", rrsig.String())
}
