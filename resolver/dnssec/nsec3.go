package dnssec

// This file contains NSEC3-based denial of existence validation per RFC 5155.

import (
	"bytes"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
)

const (
	// nsec3OptOut is the Opt-Out flag of an NSEC3 record, the only flag that is defined
	// (RFC 5155 §3.1.2)
	nsec3OptOut = 0x01

	// nsec3HashLength is the length of a SHA-1 hash, the only hash of NSEC3 (RFC 5155 §11), as an
	// NSEC3 record spells it: the 20 octets in base32hex
	nsec3HashLength = 32
)

// extractNSEC3Records extracts NSEC3 records from a list of RRs
func extractNSEC3Records(rrs []dns.RR) []*dns.NSEC3 {
	return util.ExtractRecordsFromSlice[*dns.NSEC3](rrs)
}

// nsec3Hash returns the NSEC3 hash of name in base32hex (RFC 5155 §5), made with SHA-1, the only
// hash algorithm of NSEC3. It is empty if the name or the salt cannot be hashed.
func nsec3Hash(name, salt string, iterations uint16) string {
	return dns.HashName(dns.Fqdn(strings.ToLower(name)), dns.SHA1, iterations, salt)
}

// nsec3OwnerHash returns the hash of the name that rr is for: the first label of its owner name,
// which is <hash>.<zone> (RFC 5155 §3)
func nsec3OwnerHash(rr *dns.NSEC3) string {
	hash, _, _ := strings.Cut(rr.Hdr.Name, ".")

	return hash
}

// nsec3Zone returns the zone that rr is of, in canonical form: its owner name without the first
// label, the hash (RFC 5155 §3). In the root zone the owner name is <hash>.
func nsec3Zone(rr *dns.NSEC3) string {
	_, zone, _ := strings.Cut(rr.Hdr.Name, ".")

	return dns.CanonicalName(zone)
}

// nsec3MayProve reports whether rr may be part of a proof. A validator ignores an NSEC3 record
// with a hash algorithm that it does not know, which is every one but SHA-1 (RFC 5155 §8.1), and
// one with a flag other than Opt-Out (RFC 5155 §8.2). A record whose owner name does not start
// with a SHA-1 hash, or whose next hashed owner name is none, proves nothing either.
func nsec3MayProve(rr *dns.NSEC3) bool {
	return rr.Hash == dns.SHA1 && rr.Flags&^nsec3OptOut == 0 &&
		isNSEC3Hash(nsec3OwnerHash(rr)) && isNSEC3Hash(rr.NextDomain)
}

// isNSEC3Hash reports whether hash spells a SHA-1 hash
func isNSEC3Hash(hash string) bool {
	_, err := decodeNSEC3Hash(hash)

	return err == nil && len(hash) == nsec3HashLength
}

// setNSEC3Params takes the hash parameters of the set from its first NSEC3 record and returns why
// its NSEC3 records prove nothing, if they do not: an iteration count above maxIterations
// (RFC 5155 §10.3), or records with other parameters than the first. A zone may have NSEC3 chains
// with different parameters (RFC 5155 §7.3), and a validator may treat a reply that mixes them as
// bogus (RFC 5155 §8.2). No proof hashes a name for records that prove nothing, so the iteration
// count meets its limit here and nowhere else. The hash algorithm is no parameter of the set: it
// keeps no record of another than SHA-1 (see nsec3MayProve).
func (d *denialSet) setNSEC3Params(maxIterations uint) error {
	first := d.nsec3[0]
	d.salt, d.iterations = first.Salt, first.Iterations

	if uint(d.iterations) > maxIterations {
		return fmt.Errorf("NSEC3 iteration count %d exceeds maximum %d", d.iterations, maxIterations)
	}

	for _, rr := range d.nsec3 {
		if rr.Salt != d.salt || rr.Iterations != d.iterations {
			return errors.New("inconsistent NSEC3 parameters in response")
		}
	}

	return nil
}

// hash returns the NSEC3 hash of name with the parameters of the set, which the budget of the
// validation computes (see budget.nsec3Hash). It is empty for a name that cannot be hashed and
// for a hash that the budget no longer has: no record matches or covers either.
func (d *denialSet) hash(name string) string {
	return d.b.nsec3Hash(name, d.salt, d.iterations)
}

// match returns the first NSEC3 record of the set whose owner name starts with hash, the hash of
// a name that the record then is for
func (d *denialSet) match(hash string) *dns.NSEC3 {
	for _, rr := range d.nsec3 {
		if strings.EqualFold(nsec3OwnerHash(rr), hash) {
			return rr
		}
	}

	return nil
}

// cover reports whether an NSEC3 record of the set covers hash, the hash of a name that then does
// not exist, and whether a record that covers it has the Opt-Out flag: the name may then be an
// unsigned delegation, or below one (RFC 5155 §6).
func (d *denialSet) cover(hash string) (covered, optOut bool) {
	for _, rr := range d.nsec3 {
		if nsec3HashInRange(hash, nsec3OwnerHash(rr), rr.NextDomain) {
			covered = true
			optOut = optOut || rr.Flags&nsec3OptOut != 0
		}
	}

	return covered, optOut
}

// closestEncloser returns the closest encloser of name, the longest name at or above name and in
// the zone of the set that has a matching NSEC3 record, and the next closer name, which is one
// label longer (RFC 5155 §8.3). The search goes up from name and stops at the first name that a
// record matches. The zone must hold the names below that name (see hidesNamesBelow): with a
// record that says that it does not, name has no closest encloser, as without a match. Both names
// are empty then, and the next closer name is empty if name itself has the record.
func (d *denialSet) closestEncloser(name string) (encloser, next string) {
	labels := dns.SplitDomainName(name)

	for i := range len(labels) + 1 {
		candidate := dns.Fqdn(strings.Join(labels[i:], "."))
		if !dns.IsSubDomain(d.zone, candidate) {
			break
		}

		rr := d.match(d.hash(candidate))
		if rr == nil {
			continue
		}

		if hidesNamesBelow(rr.TypeBitMap) {
			d.logger.Debugf("NSEC3 record of %s is that of a delegation or a DNAME - no closest encloser", candidate)

			break
		}

		return candidate, nextCloser(name, candidate)
	}

	return "", ""
}

// nextCloser returns the name one label longer than encloser on the way down to name. It is empty
// if name has no more labels than encloser.
func nextCloser(name, encloser string) string {
	labels := dns.SplitDomainName(name)
	extra := len(labels) - len(dns.SplitDomainName(encloser))

	if extra <= 0 {
		return ""
	}

	return dns.Fqdn(strings.Join(labels[extra-1:], "."))
}

// closestEncloserProof returns the proof that the name of the set does not exist from its NSEC3
// records (see encloserProof), for encloser, a name above the name that exists, and next, the name
// one label longer on the way down to the name (see nextCloser): an NSEC3 record covers the next
// closer name, so encloser is the closest encloser of the name (RFC 5155 §8.3). It is nil if the
// set does not hold the proof, and for a name that has no name above it to be its closest encloser
// (see closestEncloser): next is empty then.
func (d *denialSet) closestEncloserProof(encloser, next string) *encloserProof {
	if next == "" {
		d.logger.Debugf("Could not find a closest encloser above %s", d.name)

		return nil
	}

	covered, optOut := d.cover(d.hash(next))
	if !covered {
		d.logger.Debugf("Next closer name %s not covered by any NSEC3", next)

		return nil
	}

	return &encloserProof{encloser: encloser, optOut: optOut}
}

// nsec3NameError is nameError with the NSEC3 records of the set: the closest encloser proof, whose
// status the proof then has, and a record that covers the wildcard at the closest encloser
// (RFC 5155 §8.4)
func (d *denialSet) nsec3NameError() ValidationResult {
	if d.nsec3Err != nil {
		d.logger.Warnf("NSEC3 records for %s prove nothing: %v - treating as Bogus", d.name, d.nsec3Err)

		return ValidationResultBogus
	}

	proof := d.closestEncloserProof(d.closestEncloser(d.name))
	if proof == nil {
		return ValidationResultBogus
	}

	wildcard := wildcardAt(proof.encloser)
	if covered, _ := d.cover(d.hash(wildcard)); !covered {
		d.logger.Debugf("Wildcard %s not covered by any NSEC3", wildcard)

		return ValidationResultBogus
	}

	d.logger.Debugf("NSEC3 NXDOMAIN proof validated for %s", d.name)

	return proof.status()
}

// nsec3NoData proves with the NSEC3 records of the set that its name has no RRset of its type: by
// the record that matches the name (RFC 5155 §8.5, §8.6) or, without one, by the record of the
// wildcard at the closest encloser (RFC 5155 §8.7). What a record says about the type is read in
// one way (see lacksType).
func (d *denialSet) nsec3NoData() ValidationResult {
	if d.nsec3Err != nil {
		d.logger.Warnf("NSEC3 records for %s prove nothing: %v - treating as Bogus", d.name, d.nsec3Err)

		return ValidationResultBogus
	}

	if rr := d.match(d.hash(d.name)); rr != nil {
		return d.nsec3MatchNoData(rr)
	}

	return d.nsec3WildcardNoData()
}

// nsec3MatchNoData returns what rr, the NSEC3 record that matches the name of the set, says about
// its type: Secure if it shows that the name has no RRset of it
func (d *denialSet) nsec3MatchNoData(rr *dns.NSEC3) ValidationResult {
	if !d.lacksType(d.name, rr.TypeBitMap) {
		d.logger.Debugf("NSEC3 record for %s does not deny type %d", d.name, d.qtype)

		return ValidationResultBogus
	}

	d.logger.Debugf("NSEC3 NODATA proof validated for %s type %d", d.name, d.qtype)

	return ValidationResultSecure
}

// nsec3WildcardNoData is nsec3NoData for a name that no NSEC3 record matches: the name does not
// exist (see encloserProof), and the NSEC3 record of the wildcard at its closest encloser, which
// answers for the name, shows that it has no RRset of the type (RFC 5155 §8.7). The proof has the
// status of the closest encloser proof.
//
// A name without the record of such a wildcard has no DS RRset either if Opt-Out leaves it out of
// the NSEC3 chain: it may then be an insecure delegation (see optOutNoDS; issue #2365).
func (d *denialSet) nsec3WildcardNoData() ValidationResult {
	proof := d.closestEncloserProof(d.closestEncloser(d.name))
	if proof == nil {
		return ValidationResultBogus
	}

	wildcard := wildcardAt(proof.encloser)

	switch rr := d.match(d.hash(wildcard)); {
	case rr == nil && d.qtype == dns.TypeDS:
		return d.optOutNoDS(proof)
	case rr == nil:
		d.logger.Debugf("No matching NSEC3 record found for %s", d.name)

		return ValidationResultBogus
	case !d.lacksType(wildcard, rr.TypeBitMap):
		d.logger.Debugf("NSEC3 record of the wildcard %s does not deny type %d for %s", wildcard, d.qtype, d.name)

		return ValidationResultBogus
	}

	d.logger.Debugf("NSEC3 wildcard NODATA proof validated for %s type %d", d.name, d.qtype)

	return proof.status()
}

// nsec3NoDS is noDS with the NSEC3 records of the set, for a reply that is no name error. The
// record that matches the name has the type bitmap of an insecure delegation (RFC 5155 §8.9), or
// no record matches the name and Opt-Out leaves it out of the NSEC3 chain (RFC 5155 §8.6, see
// optOutNoDS). The record of a wildcard is that of no delegation, whatever its type bitmap says.
func (d *denialSet) nsec3NoDS() ValidationResult {
	if d.nsec3Err != nil {
		d.logger.Warnf("NSEC3 records for %s prove nothing: %v - treating as Bogus", d.name, d.nsec3Err)

		return ValidationResultBogus
	}

	rr := d.match(d.hash(d.name))

	switch {
	case rr == nil:
		return d.optOutNoDS(d.closestEncloserProof(d.closestEncloser(d.name)))
	case !assertsInsecureDelegation(rr.TypeBitMap):
		d.logger.Warnf("NSEC3 DS-absence proof for %s does not assert an insecure delegation "+
			"(NS bit clear or SOA/DS bit set)", d.name)

		return ValidationResultBogus
	}

	d.logger.Debugf("NSEC3 record for %s is that of a delegation without DS RRset", d.name)

	return ValidationResultSecure
}

// optOutNoDS proves with proof, the closest encloser proof of the set if it holds one, that its
// name, which no NSEC3 record matches, may be an insecure delegation that Opt-Out left out of the
// NSEC3 chain, or a name below one: a record that covers the next closer name has the Opt-Out
// flag (RFC 5155 §8.6). The proof is Insecure then.
func (d *denialSet) optOutNoDS(proof *encloserProof) ValidationResult {
	if proof == nil || !proof.optOut {
		d.logger.Debugf("No NSEC3 Opt-Out proof found for %s", d.name)

		return ValidationResultBogus
	}

	d.logger.Debugf("DS query for %s covered by NSEC3 Opt-Out - unsigned delegation", d.name)

	return proof.status()
}

// nsec3NoZoneCut is noZoneCut with the NSEC3 records of the set: the record that matches the name
// has the type bitmap of a name inside the zone
func (d *denialSet) nsec3NoZoneCut() bool {
	if d.nsec3Err != nil {
		return false
	}

	rr := d.match(d.hash(d.name))

	return rr != nil && assertsNoZoneCut(rr.TypeBitMap)
}

// decodeNSEC3Hash returns the octets of hash, which an NSEC3 record spells in base32hex without
// padding (RFC 5155 §3.3). An empty string is no hash.
func decodeNSEC3Hash(hash string) ([]byte, error) {
	octets, err := base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(hash))

	switch {
	case err != nil:
		return nil, fmt.Errorf("failed to decode hash %s: %w", hash, err)
	case len(octets) == 0:
		return nil, errors.New("empty hash")
	}

	return octets, nil
}

// compareNSEC3Hashes compares two NSEC3 hash strings as binary values per RFC 5155.
// RFC 5155 specifies that "Hash order" means "the order in which hashed owner names
// are arranged according to their numerical value, treating the leftmost (lowest
// numbered) octet as the most significant octet" (i.e., big-endian comparison).
//
// Returns:
//
//	-1 if hash1 < hash2
//	 0 if hash1 == hash2
//	+1 if hash1 > hash2
//	error if one of them is no hash
func compareNSEC3Hashes(hash1, hash2 string) (int, error) {
	b1, err := decodeNSEC3Hash(hash1)
	if err != nil {
		return 0, err
	}

	b2, err := decodeNSEC3Hash(hash2)
	if err != nil {
		return 0, err
	}

	// Compare as byte arrays (big-endian)
	return bytes.Compare(b1, b2), nil
}

// nsec3HashInRange checks if a hash falls in the NSEC3 range (ownerHash, nextHash): a record
// covers the hashes strictly between that of its owner name and its next hashed owner name, which
// both are hashes of names that exist (RFC 5155 §1.3). The range of the last record of a chain,
// whose next hash is the first of the chain, wraps around the end of the hash space: it holds the
// hashes above ownerHash and those below nextHash. The only record of a chain has its own hash as
// next hash and covers every other hash. Returns true if the hash is covered by the range, and
// false for a value that is no hash.
func nsec3HashInRange(hash, ownerHash, nextHash string) bool {
	cmpHashOwner, err := compareNSEC3Hashes(hash, ownerHash)
	if err != nil {
		return false
	}

	cmpHashNext, err := compareNSEC3Hashes(hash, nextHash)
	if err != nil {
		return false
	}

	cmpOwnerNext, err := compareNSEC3Hashes(ownerHash, nextHash)
	if err != nil {
		return false
	}

	if cmpOwnerNext < 0 {
		// Normal case: ownerHash < nextHash
		// Hash must be in range (ownerHash, nextHash)
		return cmpHashOwner > 0 && cmpHashNext < 0
	}
	// Wraparound case: ownerHash > nextHash (covers end of hash space), or the only record of a
	// chain: ownerHash == nextHash
	// Hash is covered if it's either > ownerHash OR < nextHash
	return cmpHashOwner > 0 || cmpHashNext < 0
}
