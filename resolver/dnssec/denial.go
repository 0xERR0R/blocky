package dnssec

// This file contains the denial of existence: the set of NSEC and NSEC3 records that a zone offers
// as proof about a name, and what it proves about that name (RFC 4035 §5.4, RFC 5155 §8). The NSEC
// and NSEC3 sides of the proofs are in nsec.go and nsec3.go, and the proof for an RRset that a
// wildcard gives a name is in wildcard.go.

import (
	"context"
	"slices"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// denialSet holds the NSEC and NSEC3 records that may prove something about one name and type.
// The zone that holds a name gives the denial of its existence (RFC 4035 §5.4), so a set holds
// records of one zone, each verified as the record of its owner name (see newDenialSet). Its
// proofs read a record that sits at a zone cut as what its side of the cut may say (RFC 6840
// §4.1: see hidesNamesBelow and lacksType), so the records of a zone deny nothing at or below a
// zone cut of that zone but the DS RRset of a delegation. Only newDenialSet makes a set, and
// every proof is one of its methods.
type denialSet struct {
	name  string // The name that the proofs are about (FQDN)
	qtype uint16 // The type that the proofs are about
	zone  string // The zone that the records are of, in canonical form
	nsec  []*dns.NSEC
	nsec3 []*dns.NSEC3

	// How long what the set proves holds, in seconds: until the first of the RRsets that its
	// records are of ends (see verifiedLifetime). A proof does not say which of them it read.
	lifetime uint32

	apex   canonicalName // The zone as the order of its names reads it (see nsecCovers)
	atName nsecName      // What the NSEC records show about the name (see nsecFind)

	// For the NSEC3 records: their hash parameters, which are those of the first record, and why
	// the records prove nothing with them, if they do not (see setNSEC3Params)
	salt       string
	iterations uint16
	nsec3Err   error

	b      *budget // Computes the NSEC3 hashes
	logger *logrus.Entry
}

// newDenialSet returns the denial set of zone for name and qtype from results, the RRsets of a
// section as validateSection returned them. It keeps the records that zone gives a denial with,
// in the order of the section: the NSEC and NSEC3 records of the RRsets that zone signed (see
// signer), with an owner name that zone has such a record for. That is a name at or below zone
// for an NSEC record (RFC 4035 §2.3) and <hash>.<zone> for an NSEC3 record (RFC 5155 §3), which
// must also be one that may be part of a proof (see nsec3MayProve). A zone says nothing about a
// name that is not at or below it: the set for such a name holds no record.
//
// A server answers with the records of one chain, NSEC or NSEC3 (RFC 5155 §10.4), so only the
// reply of a resolver that put it together while the zone changed from one to the other holds
// both. Each chain is a signed statement of the zone, so a set may hold both, and it proves with
// either (see either).
//
// The caller says which zone: the one that holds the RRset of name and qtype (see holder). The
// set does not know whether a zone cut lies between zone and name, and its proofs do not need to
// (see denialSet).
func (v *Validator) newDenialSet(
	ctx context.Context, zone string, results []rrsetResult, name string, qtype uint16,
) *denialSet {
	d := &denialSet{
		name: dns.Fqdn(name), qtype: qtype, zone: dns.CanonicalName(zone), b: budgetFrom(ctx), logger: v.logger,
	}

	var zoned bool
	if d.apex, zoned = canonicalNameOf(d.zone); !zoned || !dns.IsSubDomain(d.zone, d.name) {
		return d
	}

	for _, r := range results {
		if r.signer() != d.zone {
			continue
		}

		for _, rr := range r.rrs {
			if !denialOwnedIn(rr, d.zone) {
				continue
			}

			if len(d.nsec)+len(d.nsec3) == 0 || r.lifetime < d.lifetime {
				d.lifetime = r.lifetime
			}

			switch rr := rr.(type) {
			case *dns.NSEC:
				d.nsec = append(d.nsec, rr)
			case *dns.NSEC3:
				d.nsec3 = append(d.nsec3, rr)
			}
		}
	}

	if len(d.nsec3) > 0 {
		d.nsec3Err = d.setNSEC3Params(v.maxNSEC3Iterations)
	}

	d.atName = d.nsecFind(d.name)

	return d
}

// either returns what the records of d prove: what its NSEC records do (nsec) and, if that proof
// does not hold, what its NSEC3 records do (nsec3). A proof that does not hold is the zero value
// of T: Bogus, false or no proof. A set with records of one kind asks them alone, and one without
// records proves nothing. Every proof chooses between the two kinds with this, and with nothing
// else. Unbound asks in the same order (validate_nameerror_response).
func either[T comparable](d *denialSet, nsec, nsec3 func() T) T {
	var none T

	if len(d.nsec3) == 0 {
		return nsec()
	}

	if len(d.nsec) > 0 {
		if proof := nsec(); proof != none {
			return proof
		}
	}

	return nsec3()
}

// denialOwnedIn reports whether rr is an NSEC or NSEC3 record with an owner name that zone, a name
// in canonical form, has such a record for (see newDenialSet)
func denialOwnedIn(rr dns.RR, zone string) bool {
	switch rr := rr.(type) {
	case *dns.NSEC:
		return dns.IsSubDomain(zone, rr.Hdr.Name)
	case *dns.NSEC3:
		return nsec3MayProve(rr) && nsec3Zone(rr) == zone
	}

	return false
}

// denialZone returns the zone whose records in results, the RRsets of the authority section of a
// reply, may deny an RRset that the zone of holder holds (see holder): the closest zone at or
// above holder that signed NSEC or NSEC3 RRsets of the reply. The chain of trust walk went to
// that zone for the keys that verified them, so it is a zone by its zone cut, and it is on the
// chain of trust to holder: a zone above a trust anchor that covers holder does not answer for
// it, the zone of the anchor does (RFC 6840 §5.10, Appendix C.1). found is false if no such zone
// signed a denial of the reply.
//
// A zone cut may lie between that zone and holder. Nothing needs to ask: the proofs of a denial
// set let the records of a zone deny nothing at or below one of its zone cuts, so a proof that
// holds was given by the zone that holds the name, and a denial that its set does not prove
// leaves the answer what it is without one (see unansweredStatus).
func (v *Validator) denialZone(results []rrsetResult, holder string) (zone string, found bool) {
	for _, r := range results {
		signer := r.signer()
		if r.rrType != dns.TypeNSEC && r.rrType != dns.TypeNSEC3 || signer == "" {
			continue
		}

		if dns.IsSubDomain(signer, holder) && !v.hasTrustAnchorBelow(signer, holder) &&
			(!found || dns.IsSubDomain(zone, signer)) {
			zone, found = signer, true
		}
	}

	return zone, found
}

// hasDenialRecords reports whether rrs, a section as the reply holds it, has NSEC or NSEC3
// records: the reply then offers a denial. What it proves is for the denial set of the section to
// say, and a set that keeps none of the records proves nothing.
func hasDenialRecords(rrs []dns.RR) bool {
	return len(extractNSECRecords(rrs)) > 0 || len(extractNSEC3Records(rrs)) > 0
}

// encloserProof is the proof that a name does not exist and of what answers for it then. encloser
// is the closest encloser of the name: the longest name above it that exists. No name between the
// two exists, so the wildcard at encloser, and no other, answers for the name if the zone has it
// (RFC 4592 §3.3.1). Every proof about a name that does not exist rests on it:
//   - a name error: the wildcard at the closest encloser does not exist either (see nameError);
//   - "no data" by a wildcard: the record of that wildcard lacks the type (see noData);
//   - an RRset that an RRSIG made for a wildcard verified: that wildcard is the one at the closest
//     encloser (see wildcardExpansion).
//
// NSEC records give the proof by the record that covers the name (see nsecFind), NSEC3 records by
// the closest encloser proof of RFC 5155 §8.3 (see closestEncloserProof).
type encloserProof struct {
	encloser string
	optOut   bool // An NSEC3 record that covers the next closer name has the Opt-Out flag
}

// status returns the status of what rests on the proof: Secure, or Insecure if an NSEC3 record
// that covers the next closer name has the Opt-Out flag. The name may then be an unsigned
// delegation, or below one, so nothing about it is authenticated (RFC 5155 §9.2).
func (p *encloserProof) status() ValidationResult {
	if p.optOut {
		return ValidationResultInsecure
	}

	return ValidationResultSecure
}

// nameError proves that the zone has nothing for the name of the set: the name does not exist,
// and neither does the wildcard at its closest encloser, which would answer for it (RFC 4035
// §5.4, RFC 5155 §8.4; see encloserProof)
func (d *denialSet) nameError() ValidationResult {
	return either(d, d.nsecNameError, d.nsec3NameError)
}

// noData proves that the name of the set has no RRset of its type. A name has no DS RRset if it
// is a delegation without one or no zone cut at all, and either is read from the records of the
// zone above it (see lacksType).
func (d *denialSet) noData() ValidationResult {
	return either(d, d.nsecNoData, d.nsec3NoData)
}

// noDS proves that the name of the set, with type DS, is an insecure delegation (RFC 4035 §5.2).
// It is Secure for the NSEC or NSEC3 record of a delegation without DS RRset, and Insecure for a
// name that Opt-Out leaves out of the NSEC3 chain: both say that the delegation is insecure. A
// name that is no zone cut has no DS RRset either (see noData) and is no delegation: for that
// there is noZoneCut. nameError says that the reply to the DS query was a name error.
func (d *denialSet) noDS(nameError bool) ValidationResult {
	return either(d, d.nsecNoDS, func() ValidationResult {
		if !nameError {
			return d.nsec3NoDS()
		}

		// A name that does not exist is no delegation and has no keys to sign with. Only an Opt-Out
		// span (Insecure) may hold an unsigned delegation that the denial does not show (RFC 5155 §6).
		result := d.nsec3NameError()
		if result == ValidationResultSecure {
			d.logger.Warnf("NSEC3 proof shows that %s does not exist - not an unsigned delegation", d.name)

			return ValidationResultBogus
		}

		return result
	})
}

// noZoneCut proves that the name of the set is part of the zone that the records are from and no
// delegation, so that the zone signs the names below it too: its NSEC or NSEC3 record has the
// type bitmap of a name inside the zone (see assertsNoZoneCut), or an NSEC record shows that it
// is an empty non-terminal. It is the proof that a DS query for the name finds no zone cut.
func (d *denialSet) noZoneCut() bool {
	return either(d, d.nsecNoZoneCut, d.nsec3NoZoneCut)
}

// assertsNoZoneCut reports whether an NSEC/NSEC3 type bitmap shows a name inside the zone: no NS bit
// (no delegation), no SOA bit (no zone apex) and no DS bit (no DS RRset that the reply left out).
// It is the counterpart of assertsInsecureDelegation.
func assertsNoZoneCut(typeBitMap []uint16) bool {
	return !slices.Contains(typeBitMap, dns.TypeNS) &&
		!slices.Contains(typeBitMap, dns.TypeSOA) &&
		!slices.Contains(typeBitMap, dns.TypeDS)
}

// assertsInsecureDelegation reports whether an NSEC/NSEC3 type bitmap proves an insecure
// delegation per RFC 6840 §4.4 / RFC 5155 §8.9: the NS bit MUST be set and the SOA and DS
// bits MUST be clear. This single rule distinguishes a genuine unsigned delegation from an
// ordinary name inside a signed zone (NS bit clear) or the apex of a signed zone (SOA bit
// set), neither of which may be treated as an insecure delegation when proving DS absence.
func assertsInsecureDelegation(typeBitMap []uint16) bool {
	return isDelegation(typeBitMap) && !slices.Contains(typeBitMap, dns.TypeDS)
}

// isDelegation reports whether typeBitMap, the type bitmap of the NSEC or NSEC3 record of a name,
// is that of a delegation: the zone above a zone cut has the NS RRset of the name and not the SOA
// RRset, which is at the apex of the zone below (RFC 6840 §4.1)
func isDelegation(typeBitMap []uint16) bool {
	return slices.Contains(typeBitMap, dns.TypeNS) && !slices.Contains(typeBitMap, dns.TypeSOA)
}

// hidesNamesBelow reports whether typeBitMap, the type bitmap of the NSEC or NSEC3 record of a
// name, says that the zone of the record does not hold the names below that name: a delegation
// gives them to another zone, and a DNAME RRset redirects them. Such a record denies no name
// below its owner (RFC 6840 §4.1).
func hidesNamesBelow(typeBitMap []uint16) bool {
	return isDelegation(typeBitMap) || slices.Contains(typeBitMap, dns.TypeDNAME)
}

// lacksType reports whether typeBitMap, the type bitmap of the NSEC or NSEC3 record of owner,
// shows that owner has no RRset of the type of the set: it lists neither the type nor CNAME, and
// the record is from the side of a zone cut at owner that holds the type.
//
// A name that owns a CNAME RRset has no other data, and that RRset is the answer for every other
// type at the name, so its record denies no type (RFC 6840 §4.3). That holds for a DS RRset too:
// a name that owns a CNAME is no delegation. The record of a delegation lists what the zone above
// has at the name, which is no type but DS (RFC 6840 §4.1). A record with the SOA bit lists what
// a zone has at its apex, which is no DS RRset: that is the zone above's (RFC 4035 §2.4), and
// only the root has none above it.
func (d *denialSet) lacksType(owner string, typeBitMap []uint16) bool {
	switch {
	case d.qtype == dns.TypeANY:
		// ANY asks for any RRset, so every listed type counts. An empty NSEC3
		// bitmap describes an empty non-terminal at the original (unhashed) name.
		return len(typeBitMap) == 0
	case slices.Contains(typeBitMap, d.qtype), slices.Contains(typeBitMap, dns.TypeCNAME):
		return false
	case d.qtype == dns.TypeDS:
		return !slices.Contains(typeBitMap, dns.TypeSOA) || dns.Fqdn(owner) == "."
	}

	return !isDelegation(typeBitMap)
}
