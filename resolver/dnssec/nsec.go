package dnssec

// This file contains NSEC-based denial of existence validation per RFC 4035 §5.4.

import (
	"bytes"
	"slices"
	"strings"

	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
)

// maxNameOctets is the length that a name may have on the wire (RFC 1035 §2.3.4)
const maxNameOctets = 255

// extractNSECRecords extracts all NSEC records from a slice of RRs
func extractNSECRecords(rrs []dns.RR) []*dns.NSEC {
	return util.ExtractRecordsFromSlice[*dns.NSEC](rrs)
}

// nsecName is what the NSEC records of a set show about a name (see nsecFind)
type nsecName struct {
	record *dns.NSEC      // The NSEC record that the name owns, which lists the types that it has
	empty  bool           // A record covers the name and shows it to be an empty non-terminal
	absent *encloserProof // A record covers the name and shows that it does not exist
}

// nsecFind returns what the NSEC records of the set show about name (FQDN), from one search of
// them: the first record that name owns, and what the first record that covers name says. A set
// searches them for its own name once (see newDenialSet). A name that a record covers is between
// the owner name and the next owner name of that record in the order of the zone (see
// nsecCovers), so the zone has no records of it. A record that says that its zone does not hold
// the names below its owner name covers none of them (see hidesNamesBelow). Names are compared in
// canonical form (RFC 4034 §6.1, see canonicalName): a name is the same name in every case
// (RFC 4343), and a reply spells an owner name as its question does where it compresses the one
// against the other. A name that cannot be on the wire is no name of a zone: no record owns or
// covers it, and a record with such a name is passed over.
//
// A name without records exists if a name below it has some: it is an empty non-terminal
// (RFC 4592 §2.2.2), and so is a wildcard without records that has names below it (RFC 4592
// §4.9). The record that covers name then has a name below name as its next owner name, the name
// after name in the order of the zone. That is the only reading of such a record, also of one
// that a name server made up to cover name alone (RFC 4470 §4). With any other record that
// covers it, name does not exist. The owner name and the next owner name of the record are the
// names before and after name, so the closest encloser of name is the longer of what name has in
// common with either (RFC 4592 §3.3.1).
func (d *denialSet) nsecFind(name string) (found nsecName) {
	var owner, next canonicalName // Those of the first record that covers name

	labels, named := canonicalNameOf(name)
	if !named {
		return found
	}

	covered := false

	for _, rr := range d.nsec {
		from, owned := canonicalNameOf(rr.Hdr.Name)
		to, ended := canonicalNameOf(rr.NextDomain)

		if !owned || !ended {
			continue
		}

		if found.record == nil && labels.compare(from) == 0 {
			found.record = rr
		}

		hidden := hidesNamesBelow(rr.TypeBitMap) && labels.isAtOrBelow(from)
		if !covered && !hidden && d.nsecCovers(from, to, labels) {
			covered, owner, next = true, from, to
		}
	}

	switch {
	case !covered:
	case next.isAtOrBelow(labels):
		// RFC 4592 §2.2.2, §4.9: the name after name in the zone is below it, so name exists
		found.empty = true
	default:
		text := dns.SplitDomainName(name)
		shared := max(labels.shared(owner), labels.shared(next))
		found.absent = &encloserProof{encloser: dns.Fqdn(strings.Join(text[max(len(text)-shared, 0):], "."))}
	}

	return found
}

// nsecCovers reports whether name is between owner and next, the owner name and the next owner
// name of an NSEC record, in the canonical order of the zone (RFC 4034 §6.1): after the one and
// before the other. The last record of a zone has the apex of the zone as its next owner name
// (RFC 4034 §4.1.1) and covers every name of the zone after its owner name. No other record has a
// next owner name that is before its owner name.
func (d *denialSet) nsecCovers(owner, next, name canonicalName) bool {
	if name.compare(owner) <= 0 {
		return false
	}

	return next.compare(d.apex) == 0 || name.compare(next) < 0
}

// nsecNameError is nameError with the NSEC records of the set: a record shows that the name does
// not exist, and another or the same that the wildcard at its closest encloser does not exist
// either (RFC 4035 §5.4). A name or a wildcard that is an empty non-terminal exists: the answer
// for the name is then "no data" and no name error (see nsecFind).
func (d *denialSet) nsecNameError() ValidationResult {
	proof := d.atName.absent
	if proof == nil {
		d.logger.Warnf("No NSEC record shows that %s does not exist", d.name)

		return ValidationResultBogus
	}

	if wildcard := wildcardAt(proof.encloser); d.nsecFind(wildcard).absent == nil {
		d.logger.Warnf("No NSEC record shows that the wildcard %s does not exist, which answers for %s if it does",
			wildcard, d.name)

		return ValidationResultBogus
	}

	d.logger.Debugf("NSEC records prove NXDOMAIN for %s below %s", d.name, proof.encloser)

	return proof.status()
}

// nsecNoData proves with the NSEC records of the set that its name has no RRset of its type, in
// one of the forms that a zone sends the proof in (RFC 4035 §3.1.3.1, §3.1.3.4, §5.4):
//   - the NSEC record of the name lacks the type;
//   - the name is an empty non-terminal, which has no RRset of any type;
//   - the name does not exist (see encloserProof), and the wildcard at its closest encloser, which
//     answers for the name, has no RRset of the type in one of these two ways.
//
// What a record says about the type is read in one way (see lacksType).
func (d *denialSet) nsecNoData() ValidationResult {
	owner, found := d.name, d.atName
	if found.record == nil && found.absent != nil {
		owner = wildcardAt(found.absent.encloser)
		found = d.nsecFind(owner)
	}

	switch rr := found.record; {
	case rr != nil && d.qtype == dns.TypeANY:
		// Unlike NSEC3, the NSEC RRset itself is data at the owner.
		d.logger.Warnf("NSEC at %s cannot prove ANY NODATA", rr.Hdr.Name)

		return ValidationResultBogus
	case rr != nil && !d.lacksType(rr.Hdr.Name, rr.TypeBitMap):
		d.logger.Warnf("NSEC at %s does not deny type %d: it lists the type or CNAME, or it is from the side of a "+
			"zone cut that does not hold the type", rr.Hdr.Name, d.qtype)

		return ValidationResultBogus
	case rr == nil && !found.empty:
		d.logger.Warnf("No matching NSEC record found for NODATA proof: %s", d.name)

		return ValidationResultBogus
	}

	d.logger.Debugf("NSEC proves NODATA for %s type %d: %s has no RRset of it", d.name, d.qtype, owner)

	return ValidationResultSecure
}

// nsecNoDS is noDS with the NSEC records of the set: the record of the name is that of a
// delegation without DS RRset (RFC 6840 §4.4)
func (d *denialSet) nsecNoDS() ValidationResult {
	if rr := d.atName.record; rr == nil || !assertsInsecureDelegation(rr.TypeBitMap) {
		d.logger.Warnf("NSEC DS-absence proof for %s does not assert an insecure delegation "+
			"(NS bit clear or SOA/DS bit set) - not an unsigned delegation", d.name)

		return ValidationResultBogus
	}

	return ValidationResultSecure
}

// nsecNoZoneCut is noZoneCut with the NSEC records of the set: the record of the name has the type
// bitmap of a name inside the zone, or a record shows that the name is an empty non-terminal (see
// nsecFind)
func (d *denialSet) nsecNoZoneCut() bool {
	return d.atName.empty || d.atName.record != nil && assertsNoZoneCut(d.atName.record.TypeBitMap)
}

// canonicalName is a name as the canonical order of names reads it (RFC 4034 §6.1): its labels
// from the last to the first, each as the octets that are on the wire, with upper case US-ASCII
// letters as lower case. The octets decide and not the text of a name, which escapes some of
// them: a space inside a label is "\ " there. The root has no labels.
type canonicalName [][]byte

// canonicalNameOf returns name in canonical form. ok is false for a name that cannot be on the
// wire, which has no such form.
func canonicalNameOf(name string) (labels canonicalName, ok bool) {
	wire := make([]byte, maxNameOctets)
	if _, err := dns.PackDomainName(dns.Fqdn(name), wire, 0, nil, false); err != nil {
		return nil, false
	}

	for off := 0; wire[off] != 0; off += int(wire[off]) + 1 {
		label := wire[off+1 : off+1+int(wire[off])]
		for i, octet := range label {
			if octet >= 'A' && octet <= 'Z' {
				label[i] = octet - 'A' + 'a'
			}
		}

		labels = append(labels, label)
	}

	slices.Reverse(labels)

	return labels, true
}

// compare returns the order of n and other: a negative value if n is before other, 0 if they are
// the same name and a positive value if n is after other. A label is before a longer one that
// starts with it, and a name before the names below it.
func (n canonicalName) compare(other canonicalName) int {
	return slices.CompareFunc(n, other, bytes.Compare)
}

// shared returns how many labels n and other have in common, from the last one: the labels of the
// longest name that both are at or below
func (n canonicalName) shared(other canonicalName) int {
	count := 0
	for count < min(len(n), len(other)) && bytes.Equal(n[count], other[count]) {
		count++
	}

	return count
}

// isAtOrBelow reports whether n is other or a name below it
func (n canonicalName) isAtOrBelow(other canonicalName) bool {
	return n.shared(other) == len(other)
}
