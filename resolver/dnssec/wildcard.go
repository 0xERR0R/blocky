package dnssec

// This file contains wildcard expansion validation per RFC 4035 §5.3.4.

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// wildcardInSignerZone checks that rrsig, if it was made for a wildcard that the owner name of
// rrset matches and not for that name itself, was made for a wildcard in the zone of its signer
// (RFC 4035 §5.3.4)
func wildcardInSignerZone(rrset []dns.RR, rrsig *dns.RRSIG) error {
	if len(rrset) == 0 {
		return nil
	}

	owner := dns.Fqdn(rrset[0].Header().Name)
	if len(dns.SplitDomainName(owner)) <= int(rrsig.Labels) {
		return nil
	}

	wildcard, signer := wildcardAt(expansionEncloser(owner, rrsig)), dns.Fqdn(rrsig.SignerName)
	if !dns.IsSubDomain(signer, wildcard) {
		return fmt.Errorf("wildcard %s not within signer zone %s", wildcard, signer)
	}

	return nil
}

// expansionEncloser returns the name that the wildcard which rrsig was made for is below: what is
// left of owner (FQDN), a name that the wildcard matches, with the labels that the Labels field of
// rrsig counts (RFC 4035 §5.3.2). Where the wildcard answers for owner, that name is the closest
// encloser of owner (RFC 4592 §3.3.1).
func expansionEncloser(owner string, rrsig *dns.RRSIG) string {
	labels := dns.SplitDomainName(owner)

	return dns.Fqdn(strings.Join(labels[max(len(labels)-int(rrsig.Labels), 0):], "."))
}

// wildcardAt returns the wildcard below encloser, which answers for the names below encloser that
// do not exist (RFC 4592 §3.3.1)
func wildcardAt(encloser string) string {
	return "*." + strings.TrimPrefix(encloser, ".")
}

// isWildcardExpansion reports whether rrsig was made for a wildcard that owner, the owner name of
// the RRset it covers, matches: its Labels field counts fewer labels than that of an RRSIG made for
// owner itself (RFC 4035 §5.3.2). The field does not count a leading "*" label (RFC 4034 §3.1.3),
// so the records that a wildcard owns, like its NSEC record, are no expansion.
func isWildcardExpansion(owner string, rrsig *dns.RRSIG) bool {
	return rrsigLabelsForOwner(owner) > int(rrsig.Labels)
}

// wildcardExpansion returns the status of the proof that the wildcard at encloser answers for
// the name of the set, the owner name of an RRset that an RRSIG made for that wildcard verified
// (RFC 4035 §5.3.4, RFC 5155 §8.8). The RRSIG shows that the wildcard exists, and encloser with
// it. The wildcard answers for the name if encloser is the closest encloser of the name (see
// encloserProof):
//   - with NSEC records, the record that covers the name shows which name that is;
//   - with NSEC3 records, no name between encloser and the name exists if a record covers the next
//     closer name. The proof is Insecure if that record has the Opt-Out flag.
//
// A set without the proof, like one without records, gives Bogus.
func (d *denialSet) wildcardExpansion(encloser string) ValidationResult {
	proof := either(d, func() *encloserProof {
		// Both names are what is left of the name of the set without its first labels
		if shown := d.atName.absent; shown != nil && dns.CanonicalName(shown.encloser) == dns.CanonicalName(encloser) {
			return shown
		}

		return nil
	}, func() *encloserProof {
		if d.nsec3Err != nil {
			d.logger.Warnf("NSEC3 records for %s prove nothing: %v", d.name, d.nsec3Err)

			return nil
		}

		return d.closestEncloserProof(encloser, nextCloser(d.name, encloser))
	})
	if proof == nil {
		d.logger.Debugf("No proof that %s is the closest encloser of %s", encloser, d.name)

		return ValidationResultBogus
	}

	d.logger.Debugf("Wildcard %s answers for %s", wildcardAt(encloser), d.name)

	return proof.status()
}
