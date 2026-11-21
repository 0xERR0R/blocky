package dnssec

// Helpers of the universe test (universe_test.go): the zones, the honest responder, the operators
// that mutate its replies, the curated cases of known findings and the oracle. They reach the
// validator only through NewValidator and ValidateResponse, and through validate for what the
// validation of a case costs. A case that lets time pass gives the validator a cache of zones with
// a clock of its own (uniClock).

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

// Signatures are valid from 2020 to 2106-02-07, the last time an RRSIG can express, so that no
// status depends on the date of the run.
const (
	uniInception  = 1577836800
	uniExpiration = 1<<32 - 1
	uniTTL        = 3600
	uniMaxAliases = 16 // no CNAME chain of the universe is longer
)

type uniKind int

const (
	uniNSEC     uniKind = iota // signed, denials by NSEC
	uniNSEC3                   // signed, denials by NSEC3
	uniOptOut                  // signed, NSEC3 with Opt-Out: insecure delegations have no NSEC3
	uniUnsigned                // an insecure delegation of its parent zone
)

type uniZoneSpec struct {
	name    string
	kind    uniKind
	records string // zone file lines; names are relative to the zone
	ask     string // names without records to ask about too, relative to the zone; "-" asks nothing
}

// uniZoneSpecs is the universe: the root, whose key-signing key is the trust anchor, and the zones
// below it. The builder adds each zone's SOA, NS and DNSKEY RRsets, its delegation in the parent
// zone (with a DS RRset if both are signed), the NSEC or NSEC3 chain and the RRSIGs.
//
// "chain" is a CNAME chain across eight zones, and i.h.g.f.e.d.c.b.deep. a zone nine labels deep
// below zone cuts and empty non-terminals of both denial kinds. nx.alias.nsec. and nx.chain.nsec3.
// are names below a name that owns a CNAME: only the records of the zone say what is below it.
// The root and nsec3. sign with a zone-signing key; that of twin. has the key tag of its
// key-signing key. rsa. and exp4096. have RSA keys with large exponents; verifying with the
// 4096-bit one is slow, so that zone gets a single curated case and no questions.
var uniZoneSpecs = []uniZoneSpec{
	{".", uniNSEC, ``, "nx"},
	{"nsec.", uniNSEC, `
		www         A     192.0.2.1
		www         TXT   "www"
		*.wild      A     192.0.2.2
		host.wild   TXT   "a name beside the wildcard"
		a.ent       A     192.0.2.3
		alias       CNAME www.nsec3.
		dangling    CNAME nx.nsec3.
		to-insecure CNAME www.insecure.nsec.
		dname       DNAME nsec3.
		chain       CNAME chain.nsec3.`, "nx x.wild y.x.wild a.host.wild sub.www www.dname nx.alias"},
	{"sec.nsec.", uniNSEC3, `
		@           A     192.0.2.4
		www         A     192.0.2.5
		*.wild      A     192.0.2.6
		chain       CNAME chain.sec.nsec3.`, "nx a.nx y.x.wild"},
	{"insecure.nsec.", uniUnsigned, `
		www         A     192.0.2.7
		back        CNAME www.nsec.`, "nx"},
	{"under.alias.nsec.", uniNSEC, `www A 192.0.2.8`, ""}, // the DS query for alias.nsec. gets a CNAME
	{"nsec3.", uniNSEC3, `
		www         A     192.0.2.9
		*.wild      A     192.0.2.10
		host.wild   TXT   "a name beside the wildcard"
		*.cwild     CNAME www.nsec3.
		a.ent       A     192.0.2.11
		chain       CNAME chain.optout.`, "nx a.nx x.wild y.x.wild a.host.wild x.cwild nx.chain"},
	{"sec.nsec3.", uniNSEC, `
		www         A     192.0.2.12
		chain       CNAME chain.sec.optout.`, "nx"},
	{"insecure.nsec3.", uniUnsigned, `www A 192.0.2.13`, "nx"},
	{"optout.", uniOptOut, `
		www         A     192.0.2.14
		*.wild      A     192.0.2.15
		chain       CNAME chain.other.`, "nx a.nx x.wild y.x.wild"},
	{"sec.optout.", uniNSEC3, `
		www         A     192.0.2.16
		chain       CNAME chain.deep.`, "nx"},
	{"unsigned.optout.", uniUnsigned, `www A 192.0.2.17`, "nx"},
	// Signed, but Insecure below its unsigned parent unless its own key is a trust anchor
	{"island.unsigned.optout.", uniNSEC, `www A 192.0.2.18`, "nx"},
	{"one.", uniNSEC, ``, "nx"}, // its only NSEC has itself as next name
	{"other.", uniNSEC3, `
		www         A     192.0.2.19
		chain       CNAME chain.sec.nsec.`, "nx"},
	// Labels with octets that sort differently once a zone file escapes them (RFC 4034 §6.1)
	{"odd.", uniNSEC, `
		caa         A     192.0.2.20
		cafe        A     192.0.2.21
		caf\195\169 A     192.0.2.22
		dog         A     192.0.2.23`, `nx do\200`},
	// The TXT RRset sorts differently by RDATA (RFC 4034 §6.3) and by RDATA length
	{"rsa.", uniNSEC, `
		www         A     192.0.2.24
		www         TXT   "a" "bb"
		www         TXT   "b"`, "nx"},
	{"exp4096.", uniNSEC, `www A 192.0.2.25`, "-"},
	{"twin.", uniNSEC, `www A 192.0.2.26`, ""},
	{"deep.", uniNSEC, `
		www         A     192.0.2.27
		chain       A     192.0.2.28`, ""},
	{"c.b.deep.", uniNSEC3, `www A 192.0.2.29`, ""},
	{"f.e.d.c.b.deep.", uniNSEC, `www A 192.0.2.30`, ""},
	{"i.h.g.f.e.d.c.b.deep.", uniNSEC3, `www A 192.0.2.31`, "nx"},
}

// uniNSEC3Root is a second universe: a root signed with NSEC3, which is then the closest encloser
// of a top-level name that does not exist. Only its honest replies are validated.
var uniNSEC3Root = []uniZoneSpec{{".", uniNSEC3, `www A 192.0.2.32`, "nx"}}

// uniMutated lists the questions whose honest replies are mutated, one for each shape of reply.
var uniMutated = []string{
	"www.nsec./A", "www.nsec./CNAME", "x.wild.nsec./A", "alias.nsec./A", "dangling.nsec./A", "nx.nsec./A",
	"x.wild.nsec3./A", "x.wild.nsec3./TXT", "ent.nsec3./A", "a.nx.nsec3./A", "nx.optout./A", "sec.nsec./DS",
	"insecure.nsec./DS", "unsigned.optout./DS", "www.insecure.nsec./A", "to-insecure.nsec./A",
	"ent.nsec./A", "x.wild.nsec./TXT",
}

// uniSubMutated lists the questions whose honest replies are validated with one of the validator's
// own DS or DNSKEY queries failing or answered by a mutated reply: each query under the first
// question that makes the validator ask it.
var uniSubMutated = []string{
	"www.sec.nsec./A", "www.insecure.nsec./A", "www.unsigned.optout./A", "www.rsa./A", "www.sec.optout./A",
	"www.sec.nsec3./A", "www.insecure.nsec3./A", "www.c.b.deep./A", "www.f.e.d.c.b.deep./A",
}

type uniKey struct {
	*dns.DNSKEY

	priv crypto.Signer
}

func (k uniKey) sign(rrset []dns.RR) *dns.RRSIG {
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{Ttl: uniTTL}, Algorithm: k.Algorithm, KeyTag: k.KeyTag(), SignerName: k.Hdr.Name,
		Inception: uniInception, Expiration: uniExpiration,
	}
	Expect(sig.Sign(k.priv, rrset)).Should(Succeed())

	return sig
}

// signed returns rrset followed by the RRSIG that k makes for it.
func (k uniKey) signed(rrset []dns.RR) []dns.RR { return append(slices.Clone(rrset), k.sign(rrset)) }

// uniEd25519Key returns an Ed25519 key of zone made from seed, so that keys and signatures are the
// same in every run.
func uniEd25519Key(zone string, flags uint16, seed string) uniKey {
	sum := sha256.Sum256([]byte("universe test key: " + seed))
	priv := ed25519.NewKeyFromSeed(sum[:])
	public := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))

	return uniKey{&dns.DNSKEY{
		Hdr: uniHdr(zone, dns.TypeDNSKEY), Flags: flags, Protocol: 3, Algorithm: dns.ED25519, PublicKey: public,
	}, priv}
}

// uniRSAKeys reads the DNSKEY RRset of zone from testdata: RSA keys with public exponents that
// crypto/rsa neither makes nor signs with. rsa. has an RSA/SHA-256 key that signs the zone, an
// RSA/SHA-1 zone key that signs nothing and an RSA/SHA-256 key without the Zone Key flag, all with
// the exponent 2^32+1; the key of exp4096. has an exponent of 4096 bits.
func uniRSAKeys(zone string) []uniKey {
	data, err := os.ReadFile("testdata/universe-rsa-keys.txt")
	Expect(err).Should(Succeed())

	var keys []uniKey

	for line := range strings.Lines(string(data)) {
		var (
			alg     uint8
			flags   uint16
			e, n, d = new(big.Int), new(big.Int), new(big.Int)
		)

		if !strings.HasPrefix(line, zone+" ") {
			continue
		}

		_, err := fmt.Sscanf(strings.TrimPrefix(line, zone), "%d %d %x %x %x", &alg, &flags, e, n, d)
		Expect(err).Should(Succeed())

		// RFC 3110 §2: the length of the exponent in one octet, or in two after a zero octet, the
		// exponent and the modulus
		length := []byte{byte(len(e.Bytes()))}
		if len(e.Bytes()) > 255 {
			length = []byte{0, byte(len(e.Bytes()) >> 8), byte(len(e.Bytes()))}
		}

		public := base64.StdEncoding.EncodeToString(slices.Concat(length, e.Bytes(), n.Bytes()))
		keys = append(keys, uniKey{&dns.DNSKEY{
			Hdr: uniHdr(zone, dns.TypeDNSKEY), Flags: flags, Protocol: 3, Algorithm: alg, PublicKey: public,
		}, uniRSASigner{n, d}})
	}

	return keys
}

// uniRSASigner makes RSASSA-PKCS1-v1_5 SHA-256 signatures (RFC 8017 §8.2.1) with math/big.
type uniRSASigner struct{ n, d *big.Int }

func (s uniRSASigner) Public() crypto.PublicKey { return nil } // RRSIG.Sign does not use it

func (s uniRSASigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	// EM = 0x00 0x01 0xff ... 0xff 0x00 DigestInfo
	digestInfo := "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20" + string(digest)
	em := bytes.Repeat([]byte{0xff}, (s.n.BitLen()+7)/8)
	em[0], em[1], em[len(em)-len(digestInfo)-1] = 0, 1, 0
	copy(em[len(em)-len(digestInfo):], digestInfo)

	return new(big.Int).Exp(new(big.Int).SetBytes(em), s.d, s.n).FillBytes(em), nil
}

type uniZone struct {
	uniZoneSpec

	keys   []uniKey                       // the DNSKEY RRset; keys[0] signs it and has the DS record
	zsk    int                            // the key that signs the other RRsets
	rrsets map[string]map[uint16][]dns.RR // owner name → type → RRset
	chain  []dns.RR                       // the NSEC chain in canonical order, or the NSEC3 chain in hash order
	sigs   map[dns.RR]*dns.RRSIG          // first record of a signed RRset → its RRSIG
}

type universe struct {
	prefix string // of the case ids
	zones  []*uniZone
	logger *logrus.Entry
	signed []uniPart           // every signed RRset, in a fixed order
	pool   map[string]string   // text of every signed RRset → text of its RRSIG
	truths map[string]uniTruth // the honest replies made so far
}

// newUniverse builds and signs the zones of specs.
func newUniverse(prefix string, specs []uniZoneSpec) *universe {
	u := &universe{prefix: prefix, pool: map[string]string{}, truths: map[string]uniTruth{}}
	u.logger = logrus.NewEntry(logrus.New())
	u.logger.Logger.SetOutput(io.Discard)
	u.logger.Logger.SetLevel(logrus.PanicLevel)

	for _, spec := range specs {
		z := &uniZone{uniZoneSpec: spec, rrsets: map[string]map[uint16][]dns.RR{}, sigs: map[dns.RR]*dns.RRSIG{}}
		u.zones = append(u.zones, z)

		z.add("@ SOA ns hostmaster 1 3600 600 86400 3600", "@ NS ns")
		z.add(strings.Split(spec.records, "\n")...)

		if z.kind == uniUnsigned {
			continue
		}

		ksk := uniEd25519Key(z.name, 257, z.name+" ksk")

		switch z.name {
		case "rsa.", "exp4096.":
			z.keys = uniRSAKeys(z.name)
		case ".", "nsec3.":
			z.keys, z.zsk = []uniKey{ksk, uniEd25519Key(z.name, 256, z.name+" zsk")}, 1
		case "twin.": // the first seed of this form that gives the key tag of the key-signing key
			z.keys, z.zsk = []uniKey{ksk, uniEd25519Key(z.name, 256, "twin. zsk 58162")}, 1
			Expect(z.keys[1].KeyTag()).Should(Equal(ksk.KeyTag()))
		default:
			z.keys = []uniKey{ksk}
		}

		for _, key := range z.keys {
			z.put(key.DNSKEY)
		}

		if z.kind != uniNSEC {
			z.add("@ NSEC3PARAM 1 0 0 -")
		}
	}

	for _, z := range u.zones[1:] {
		parent := u.zoneOf(z.name, dns.TypeDS)
		parent.rrsets[z.name] = map[uint16][]dns.RR{dns.TypeNS: z.rrsets[z.name][dns.TypeNS]}

		if z.kind != uniUnsigned && parent.kind != uniUnsigned {
			parent.rrsets[z.name][dns.TypeDS] = []dns.RR{z.keys[0].ToDS(dns.SHA256)}
		}
	}

	for _, z := range u.zones {
		for _, p := range z.seal() {
			u.signed = append(u.signed, p)
			u.pool[uniText(p.rrs)] = uniText(p.sigs)
		}
	}

	return u
}

func uniHdr(name string, rtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: rtype, Class: dns.ClassINET, Ttl: uniTTL}
}

// uniRR parses a zone file line whose names are relative to origin.
func uniRR(origin, line string) dns.RR {
	rr, err := dns.NewRR("$ORIGIN " + origin + "\n" + line)
	Expect(err).Should(Succeed())

	return rr
}

func (z *uniZone) add(lines ...string) {
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			z.put(uniRR(z.name, line))
		}
	}
}

func (z *uniZone) put(rr dns.RR) {
	owner := rr.Header().Name
	if z.rrsets[owner] == nil {
		z.rrsets[owner] = map[uint16][]dns.RR{}
	}

	z.rrsets[owner][rr.Header().Rrtype] = append(z.rrsets[owner][rr.Header().Rrtype], rr)
}

// signer returns the key that signs the zone's RRsets other than its DNSKEY RRset.
func (z *uniZone) signer() uniKey { return z.keys[z.zsk] }

// seal builds the zone's NSEC or NSEC3 chain and signs every RRset the zone is authoritative for:
// all but the NS RRsets of its delegations. It returns the signed RRsets in a fixed order.
func (z *uniZone) seal() []uniPart {
	if z.kind == uniUnsigned {
		return nil
	}

	var rrsets [][]dns.RR

	owners := slices.SortedFunc(maps.Keys(z.rrsets), uniCompare)
	for _, owner := range owners {
		for _, rtype := range slices.Sorted(maps.Keys(z.rrsets[owner])) {
			if rtype != dns.TypeNS || owner == z.name {
				rrsets = append(rrsets, z.rrsets[owner][rtype])
			}
		}
	}

	z.chain = z.denialChain(owners)
	for _, denial := range z.chain {
		rrsets = append(rrsets, []dns.RR{denial})
	}

	signed := make([]uniPart, len(rrsets))
	for i, rrset := range rrsets {
		key := z.signer()
		if rrset[0].Header().Rrtype == dns.TypeDNSKEY {
			key = z.keys[0]
		}

		z.sigs[rrset[0]] = key.sign(rrset)
		signed[i] = uniPart{rrs: rrset, sigs: []dns.RR{z.sigs[rrset[0]]}}
	}

	return signed
}

// denialChain returns the NSEC chain of the zone, whose owner names are owners in canonical order,
// or its NSEC3 chain (SHA-1, no salt, no extra iterations).
func (z *uniZone) denialChain(owners []string) []dns.RR {
	var chain []dns.RR

	if z.kind == uniNSEC {
		for i, owner := range owners {
			next := owners[(i+1)%len(owners)]
			chain = append(chain, &dns.NSEC{Hdr: uniHdr(owner, dns.TypeNSEC), NextDomain: next, TypeBitMap: z.types(owner)})
		}

		return chain
	}

	// RFC 5155 §7.1: every name has an NSEC3, the empty non-terminals too; with Opt-Out the
	// insecure delegations have none.
	names := map[string]string{} // hash → name

	var flags uint8
	if z.kind == uniOptOut {
		flags = 1
	}

	for _, owner := range owners {
		if z.kind == uniOptOut && z.insecureCut(owner) {
			continue
		}

		for name := owner; ; name = uniParent(name) {
			names[dns.HashName(name, dns.SHA1, 0, "")] = name

			if name == z.name {
				break
			}
		}
	}

	hashes := slices.Sorted(maps.Keys(names))
	for i, hash := range hashes {
		chain = append(chain, &dns.NSEC3{
			Hdr:  uniHdr(uniJoin(strings.ToLower(hash), z.name), dns.TypeNSEC3),
			Hash: dns.SHA1, Flags: flags, HashLength: sha1.Size, NextDomain: hashes[(i+1)%len(hashes)],
			TypeBitMap: z.types(names[hash]),
		})
	}

	return chain
}

// types returns the type bitmap of the NSEC or NSEC3 of name: the types of its RRsets, RRSIG if the
// zone signs one of them, and NSEC.
func (z *uniZone) types(name string) []uint16 {
	types := slices.Collect(maps.Keys(z.rrsets[name]))

	switch {
	case z.kind == uniNSEC:
		types = append(types, dns.TypeRRSIG, dns.TypeNSEC)
	case len(types) > 0 && !z.insecureCut(name):
		types = append(types, dns.TypeRRSIG)
	}

	slices.Sort(types)

	return types
}

// insecureCut reports whether name is a delegation of the zone without a DS RRset.
func (z *uniZone) insecureCut(name string) bool {
	return name != z.name && z.rrsets[name][dns.TypeNS] != nil && z.rrsets[name][dns.TypeDS] == nil
}

// exists reports whether the zone has name: with records, or as an empty non-terminal.
func (z *uniZone) exists(name string) bool {
	for owner := range z.rrsets {
		if dns.IsSubDomain(name, owner) {
			return true
		}
	}

	return false
}

// encloser returns the closest ancestor of name that exists in the zone and the next closer name:
// the one below that ancestor on the way to name.
func (z *uniZone) encloser(name string) (ce, nc string) {
	for nc = name; ; nc = ce {
		if ce = uniParent(nc); z.exists(ce) || ce == "." {
			return ce, nc
		}
	}
}

// denials returns, once each and followed by their RRSIGs, the NSEC or NSEC3 records that match
// names or, for a name that has none, cover it.
func (z *uniZone) denials(names ...string) []dns.RR {
	var out []dns.RR

	if len(z.chain) == 0 {
		return nil
	}

	for _, name := range names {
		hash := strings.ToLower(dns.HashName(name, dns.SHA1, 0, ""))

		// The last record at or before name. The last of the chain covers what sorts before the first.
		at := z.chain[len(z.chain)-1]

		for _, denial := range z.chain {
			owner := denial.Header().Name
			if z.kind == uniNSEC && uniCompare(owner, name) <= 0 || z.kind != uniNSEC && owner[:len(hash)] <= hash {
				at = denial
			}
		}

		if !slices.Contains(out, at) {
			out = append(out, at, z.sigs[at])
		}
	}

	return out
}

// signedAs returns copies of rrset and, if the zone signs it, its RRSIG, owned by owner: the name
// that a wildcard RRset answers for.
func (z *uniZone) signedAs(rrset []dns.RR, owner string) []dns.RR {
	out := slices.Clone(rrset)
	if sig := z.sigs[rrset[0]]; sig != nil {
		out = append(out, sig)
	}

	return uniOwned(out, func(string) string { return owner })
}

func (z *uniZone) signed(rrset []dns.RR) []dns.RR {
	return z.signedAs(rrset, rrset[0].Header().Name)
}

func (z *uniZone) soa() []dns.RR { return z.signed(z.rrsets[z.name][dns.TypeSOA]) }

// uniOwned returns copies of rrs with their owner names changed by rename.
func uniOwned(rrs []dns.RR, rename func(string) string) []dns.RR {
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		out[i] = dns.Copy(rr)
		out[i].Header().Name = rename(rr.Header().Name)
	}

	return out
}

func uniCopy(rrs []dns.RR) []dns.RR { return uniOwned(rrs, func(name string) string { return name }) }

// uniCompare orders names canonically (RFC 4034 §6.1): label by label from the right, as the octet
// strings that are on the wire, a name before the names below it. The universe has no upper case.
func uniCompare(a, b string) int {
	labels := func(name string) [][]byte {
		var out [][]byte

		wire := make([]byte, 256)
		_, err := dns.PackDomainName(name, wire, 0, nil, false)
		Expect(err).Should(Succeed())

		for off := 0; wire[off] != 0; off += int(wire[off]) + 1 {
			out = append([][]byte{wire[off+1 : off+1+int(wire[off])]}, out...)
		}

		return out
	}

	return slices.CompareFunc(labels(a), labels(b), bytes.Compare)
}

func uniParent(name string) string {
	_, parent, _ := strings.Cut(name, ".")

	return dns.Fqdn(parent)
}

func uniJoin(label, name string) string { return label + "." + strings.TrimPrefix(name, ".") }

func uniID(name string, qtype uint16) string {
	return strings.ToLower(name) + "/" + dns.TypeToString[qtype]
}

func uniQuestion(id string) dns.Question {
	name, qtype, _ := strings.Cut(id, "/")

	return dns.Question{Name: name, Qtype: dns.StringToType[qtype], Qclass: dns.ClassINET}
}

// zoneOf returns the zone that answers for name and qtype: the deepest one that encloses name, or
// its parent zone for the DS RRset of a zone apex.
func (u *universe) zoneOf(name string, qtype uint16) *uniZone {
	best := u.zones[0]
	for _, z := range u.zones {
		if dns.IsSubDomain(z.name, name) && len(z.name) > len(best.name) && (qtype != dns.TypeDS || z.name != name) {
			best = z
		}
	}

	return best
}

func (u *universe) zone(name string) *uniZone { return u.zoneOf(name, dns.TypeSOA) }

// secure reports whether a chain of trust leads to z from the root or from one of the zones
// anchors, whose keys are trust anchors too.
func (u *universe) secure(z *uniZone, anchors []string) bool {
	for z.kind != uniUnsigned && z != u.zones[0] && !slices.Contains(anchors, z.name) {
		z = u.zoneOf(z.name, dns.TypeDS)
	}

	return z.kind != uniUnsigned
}

// questions returns the questions of the universe: for every name that exists or is asked about,
// the types A, CNAME, DS and TXT, and at a zone apex NS, SOA and DNSKEY too.
func (u *universe) questions() []string {
	ids := map[string]bool{}

	for _, z := range u.zones {
		names := strings.Fields(z.ask)
		for i, name := range names {
			names[i] = uniJoin(name, z.name)
		}

		for owner := range z.rrsets {
			for name := owner; name != z.name; name = uniParent(name) {
				names = append(names, name)
			}
		}

		for _, name := range append(names, z.name) {
			types := []uint16{dns.TypeA, dns.TypeCNAME, dns.TypeDS, dns.TypeTXT}
			if u.zone(name).name == name {
				types = append(types, dns.TypeNS, dns.TypeSOA, dns.TypeDNSKEY)
			}

			for _, qtype := range types {
				if u.zone(name).ask != "-" {
					ids[uniID(name, qtype)] = true
				}
			}
		}
	}

	return slices.Sorted(maps.Keys(ids))
}

// uniTruth is the honest reply to a question and what a validator must make of it.
type uniTruth struct {
	msg    *dns.Msg
	status ValidationResult
	// answer and proof count the leading records of the answer and authority sections that signed
	// zones vouch for: all of them if status is Secure, else those before the first unsigned or
	// opted-out link of the chain.
	answer, proof int
}

// reply returns the honest reply to a question for a validator whose trust anchors are the keys
// of the root and of the zones anchors. The reply is what a correct recursive resolver sends when
// the DO bit is set: every RRset of a signed zone with its RRSIG, CNAMEs followed across zones,
// and the NSEC or NSEC3 records that prove a wildcard or negative answer. Its answer section and
// rcode are the only true claims about the question.
func (u *universe) reply(question string, anchors ...string) uniTruth {
	key := strings.Join(append([]string{question}, anchors...), " ")
	if truth, found := u.truths[key]; found {
		return truth
	}

	q := uniQuestion(question)
	truth := uniTruth{msg: &dns.Msg{Response: true, Question: []dns.Question{q}}, status: ValidationResultSecure}

	u.chase(&truth, q, anchors)

	if truth.status == ValidationResultSecure {
		truth.answer, truth.proof = len(truth.msg.Answer), len(truth.msg.Ns)
	}

	u.truths[key] = truth

	return truth
}

// chase fills truth with the answer to q, zone by zone.
func (u *universe) chase(truth *uniTruth, q dns.Question, anchors []string) {
	m, name := truth.msg, q.Name

	for range uniMaxAliases {
		z := u.zoneOf(name, q.Qtype)
		ce, nc := z.encloser(name)
		wild := uniJoin("*", ce)
		absent := !z.exists(name)

		// RFC 5155 §9.2: what only an Opt-Out NSEC3 covers may be an insecure delegation
		optedOut := z.kind == uniOptOut && (absent || z.insecureCut(name))
		if truth.status == ValidationResultSecure && (optedOut || !u.secure(z, anchors)) {
			truth.status, truth.answer, truth.proof = ValidationResultInsecure, len(m.Answer), len(m.Ns)
		}

		// The records of name answer or, for a name that does not exist, those of the wildcard at
		// its closest encloser, with the denial of the next closer name.
		owner, proof := name, []string(nil)
		if absent {
			owner, proof = wild, []string{nc}
		}

		rrset := z.rrsets[owner][q.Qtype]
		if rrset == nil {
			rrset = z.rrsets[owner][dns.TypeCNAME]
		}

		if dname := z.rrsets[ce][dns.TypeDNAME]; absent && dname != nil {
			// RFC 6672 §2.3: the DNAME and the unsigned CNAME made from it
			m.Answer = append(m.Answer, z.signed(dname)...)
			rrset = []dns.RR{&dns.CNAME{
				Hdr: uniHdr(name, dns.TypeCNAME), Target: strings.TrimSuffix(name, ce) + dname[0].(*dns.DNAME).Target,
			}}
			proof = nil
		}

		if rrset == nil {
			switch {
			case absent && z.kind == uniNSEC: // name error, or no data at the wildcard
				proof = []string{nc, wild}
			case absent: // RFC 5155 §7.2.2, §7.2.5: with the closest encloser
				proof = []string{ce, nc, wild}
			case optedOut: // RFC 5155 §7.2.4: a DS RRset below an Opt-Out span
				proof = []string{ce, nc}
			default: // the NSEC or NSEC3 of name shows that it has no such type
				proof = []string{name}
			}

			if absent && !z.exists(wild) {
				m.Rcode = dns.RcodeNameError
			}

			m.Ns = uniAppendNew(append(m.Ns, z.soa()...), z.denials(proof...))

			return
		}

		m.Answer = append(m.Answer, z.signedAs(rrset, name)...)
		m.Ns = uniAppendNew(m.Ns, z.denials(proof...))

		alias, isAlias := rrset[0].(*dns.CNAME)
		if !isAlias || q.Qtype == dns.TypeCNAME {
			return
		}

		name = alias.Target
	}
}

// uniAppendNew appends to rrs the records of more that rrs does not hold yet: a reply holds the
// NSEC or NSEC3 record that serves two of its proofs once.
func uniAppendNew(rrs, more []dns.RR) []dns.RR {
	for _, rr := range more {
		if !slices.Contains(rrs, rr) {
			rrs = append(rrs, rr)
		}
	}

	return rrs
}

// uniPart is one RRset of a reply's answer (section 0) or authority (section 1) section with the
// RRSIGs that cover it there. rrs is empty for RRSIGs that cover no RRset of their section.
type uniPart struct {
	section int
	rrs     []dns.RR
	sigs    []dns.RR
}

// uniParts splits the answer and authority sections of m into RRsets, in their order.
func uniParts(m *dns.Msg) []uniPart {
	var parts []uniPart

	for section, rrs := range [][]dns.RR{m.Answer, m.Ns} {
		index := map[string]int{}

		for _, rr := range rrs {
			covered := rr.Header().Rrtype

			sig, isSig := rr.(*dns.RRSIG)
			if isSig {
				covered = sig.TypeCovered
			}

			key := uniID(rr.Header().Name, covered)
			if _, ok := index[key]; !ok {
				index[key] = len(parts)
				parts = append(parts, uniPart{section: section})
			}

			if p := &parts[index[key]]; isSig {
				p.sigs = append(p.sigs, rr)
			} else {
				p.rrs = append(p.rrs, rr)
			}
		}
	}

	return parts
}

// uniReply returns a copy of m whose answer and authority sections hold copies of parts.
func uniReply(m *dns.Msg, parts ...uniPart) *dns.Msg {
	out := m.Copy()
	out.Answer, out.Ns = nil, nil

	for _, p := range parts {
		if rrs := uniCopy(slices.Concat(p.rrs, p.sigs)); p.section == 0 {
			out.Answer = append(out.Answer, rrs...)
		} else {
			out.Ns = append(out.Ns, rrs...)
		}
	}

	return out
}

// uniLines returns the records of rrs that keep admits (all, if it is nil) as lines of text that
// equal records share whatever the case of their owner names and their TTLs: sorted, each once.
func uniLines(rrs []dns.RR, keep func(dns.RR) bool) []string {
	var lines []string

	for _, rr := range uniOwned(rrs, strings.ToLower) {
		if keep == nil || keep(rr) {
			rr.Header().Ttl = 0
			lines = append(lines, rr.String())
		}
	}

	slices.Sort(lines)

	return slices.Compact(lines)
}

func uniText(rrs []dns.RR) string { return strings.Join(uniLines(rrs, nil), "\n") }

// uniJunk returns an RRSIG over the RRset of owner and rtype that names key and holds a signature
// of fixed bytes that verifies nothing.
func uniJunk(owner string, rtype uint16, key *dns.DNSKEY) *dns.RRSIG {
	junk := sha512.Sum512([]byte(owner))

	return &dns.RRSIG{
		Hdr: uniHdr(owner, dns.TypeRRSIG), TypeCovered: rtype, Algorithm: key.Algorithm, OrigTtl: uniTTL,
		Labels: uint8(dns.CountLabel(owner)), Inception: uniInception, Expiration: uniExpiration,
		KeyTag: key.KeyTag(), SignerName: key.Hdr.Name, Signature: base64.StdEncoding.EncodeToString(junk[:]),
	}
}

// uniFailing returns n copies of sig that are valid in different periods, so none verifies.
func uniFailing(sig dns.RR, n int) []dns.RR {
	out := make([]dns.RR, n)
	for i := range out {
		failing := dns.Copy(sig).(*dns.RRSIG)
		failing.Inception += uint32(i + 1)
		out[i] = failing
	}

	return out
}

type uniMutant struct {
	name string
	msg  *dns.Msg
	same bool // msg means what the honest reply means, so it must get the true status
}

// mutations returns variants of m, the honest reply to question. Each is named after its operator
// and the RRset it changes: an0 is the first RRset of the answer section, ns1 the second of the
// authority section. Most are wrong. Those that mean the same are marked: another case of an
// owner name (RFC 4343), no SOA beside a proof, one more RRSIG that fails beside the one that
// verifies (RFC 6840 §5.4), a name error behind a CNAME without its rcode, and the reply to
// another question if it is the same reply. A duplicated record is a protocol error that a
// validator may forgive (RFC 4034 §6.3), and no RFC says what an RRSIG without its RRset does to
// a reply, so those are not.
func (u *universe) mutations(question string, m *dns.Msg) []uniMutant {
	var out []uniMutant

	q := uniQuestion(question)
	parts := uniParts(m)
	add := func(name string, same bool, parts ...uniPart) {
		out = append(out, uniMutant{name, uniReply(m, parts...), same})
	}
	count := [2]int{}

	for i, p := range parts {
		pos := fmt.Sprintf(".%s%d", [2]string{"an", "ns"}[p.section], count[p.section])
		count[p.section]++

		// with adds the variant that has the RRsets to in the place of p.
		with := func(name string, same bool, to ...uniPart) {
			add(name+pos, same, slices.Concat(parts[:i], to, parts[i+1:])...)
		}
		owned := func(rename func(string) string) uniPart {
			return uniPart{p.section, uniOwned(p.rrs, rename), uniOwned(p.sigs, rename)}
		}

		with("drop", p.section == 1 && p.rrs[0].Header().Rrtype == dns.TypeSOA)
		with("dup", false, p, p)
		with("move", false, uniPart{1 - p.section, p.rrs, p.sigs})
		with("rename", false, owned(func(name string) string { return uniJoin("x", name) }))
		with("upper", true, owned(strings.ToUpper))

		signer := ""
		if len(p.sigs) > 0 {
			signer = p.sigs[0].(*dns.RRSIG).SignerName

			with("unsign", false, uniPart{p.section, p.rrs, nil})
			with("sigonly", false, uniPart{p.section, nil, p.sigs})
			with("nine", false, uniPart{p.section, p.rrs, append(uniFailing(p.sigs[0], 9), p.sigs...)})
		}

		// A validly signed RRset of the same type: of another name of the zone, and of another zone
		var sameZone, otherZone bool

		for _, donor := range u.signed {
			switch donorSigner := donor.sigs[0].(*dns.RRSIG).SignerName; {
			case donor.rrs[0].Header().Rrtype != p.rrs[0].Header().Rrtype || uniText(donor.rrs) == uniText(p.rrs):
			case donorSigner == signer && !sameZone:
				sameZone = true

				with("subst-name", false, uniPart{p.section, donor.rrs, donor.sigs})
			case donorSigner != signer && !otherZone:
				otherZone = true

				with("subst-zone", false, uniPart{p.section, donor.rrs, donor.sigs})
			}
		}

		// The bit of the query type flipped in a type bitmap, and the Opt-Out flag flipped
		bit, flag := dns.Copy(p.rrs[0]), dns.Copy(p.rrs[0])
		switch denial := bit.(type) {
		case *dns.NSEC:
			denial.TypeBitMap = uniFlipType(denial.TypeBitMap, q.Qtype)

			with("bit", false, uniPart{p.section, []dns.RR{bit}, p.sigs})
		case *dns.NSEC3:
			denial.TypeBitMap = uniFlipType(denial.TypeBitMap, q.Qtype)
			flag.(*dns.NSEC3).Flags ^= 1

			with("bit", false, uniPart{p.section, []dns.RR{bit}, p.sigs})
			with("flag", false, uniPart{p.section, []dns.RR{flag}, p.sigs})
		}
	}

	// A name error behind a CNAME may come without its rcode (RFC 2308 §2.2.1, RFC 6604 §3)
	rcode := uniReply(m, parts...)
	rcode.Rcode ^= dns.RcodeNameError // NOERROR becomes NXDOMAIN, and NXDOMAIN NOERROR
	out = append(out, uniMutant{"rcode", rcode, m.Rcode == dns.RcodeNameError && len(m.Answer) > 0})

	// One more RRSIG beside the first RRset: a valid one that covers a record of another zone, and
	// one that covers the RRset, names the key of the nearest signed zone and does not verify.
	first := parts[0].rrs[0].Header()

	z := u.zoneOf(first.Name, first.Rrtype)
	for z.kind == uniUnsigned {
		z = u.zoneOf(z.name, dns.TypeDS)
	}

	junk := uniJunk(first.Name, first.Rrtype, z.signer().DNSKEY)
	add("stray-sig", false, append(parts, uniPart{parts[0].section, nil, u.zone("other.").soa()[1:]})...)
	add("junk-sig", len(parts[0].sigs) > 0, append(parts, uniPart{parts[0].section, nil, []dns.RR{junk}})...)

	// One more RRset in the authority section: the SOA RRset of an insecure zone, as that zone holds
	// it, and with an RRSIG that names the zone as its signer. Neither is authentic, so a reply
	// that holds one may not be Secure, and what the trust anchor vouches for may not become
	// Insecure by it.
	soa := u.zone("insecure.nsec.").rrsets["insecure.nsec."][dns.TypeSOA]
	madeUp := uniJunk("insecure.nsec.", dns.TypeSOA, z.signer().DNSKEY)
	madeUp.SignerName = "insecure.nsec."
	add("insecure-soa", false, append(parts, uniPart{1, soa, nil})...)
	add("insecure-soa-sig", false, append(parts, uniPart{1, soa, []dns.RR{madeUp}})...)

	// The honest reply to another question in the place of m
	otherType := "/A"
	if q.Qtype == dns.TypeA {
		otherType = "/TXT"
	}

	for _, replay := range [][2]string{
		{"type", q.Name + otherType},
		{"nx", uniID(uniJoin("nx", u.zoneOf(q.Name, q.Qtype).name), q.Qtype)},
		{"other", uniID("www.other.", q.Qtype)},
		{"insecure", uniID("insecure.nsec.", q.Qtype)},
		{"optout", uniID("unsigned.optout.", q.Qtype)},
		{"cname", uniID("alias.nsec.", q.Qtype)},
	} {
		if r := u.reply(replay[1]).msg; replay[1] != question {
			same := r.Rcode == m.Rcode && uniText(r.Answer) == uniText(m.Answer) && uniText(r.Ns) == uniText(m.Ns)
			out = append(out, uniMutant{"replay." + replay[0], r.Copy(), same})
		}
	}

	return out
}

// respelt returns the case of the honest reply to question as a resolver sends it for a query that
// spells the name in upper case: an owner name is spelt like the query name as far as it ends
// with the labels of that name, which is where the resolver compresses it against the question
// (RFC 1035 §4.1.4). The reply means what the honest reply means (RFC 4343).
func (u *universe) respelt(question string) uniCase {
	truth := u.reply(question)
	qname := strings.ToUpper(uniQuestion(question).Name)
	echo := func(name string) string {
		shared, _ := dns.PrevLabel(name, dns.CompareDomainName(name, qname))

		return name[:shared] + strings.ToUpper(name[shared:])
	}

	c := uniCase{id: question + "+upper.qname", question: question, msg: truth.msg.Copy(), want: truth.status.String()}
	c.qname, c.msg.Question[0].Name = qname, qname
	c.msg.Answer, c.msg.Ns = uniOwned(c.msg.Answer, echo), uniOwned(c.msg.Ns, echo)

	return c
}

// uniFlipType returns the sorted type bitmap types with rtype added, or removed if it is there.
func uniFlipType(types []uint16, rtype uint16) []uint16 {
	i, found := slices.BinarySearch(types, rtype)
	if found {
		return slices.Delete(slices.Clone(types), i, i+1)
	}

	return slices.Insert(slices.Clone(types), i, rtype)
}

// uniCase is a reply to validate as the answer to a question.
type uniCase struct {
	id       string
	question string // as uniID spells it: "www.nsec./A"
	msg      *dns.Msg
	// want is the status that the reply must get: that of the honest reply if it means the same,
	// Bogus if it is an attack, or one of several ("Insecure|Bogus") where the RFCs leave a
	// choice. Without it the oracle judges the status that the reply gets.
	want string
	// sub holds, by uniID, replies to the validator's own queries that replace the honest ones; a
	// nil reply makes the query fail. With once, each of them answers one query only, and the
	// status that counts is that of a second validation, made when the validator has forgotten
	// the zones that failed in the first (see uniClock).
	sub  map[string]*dns.Msg
	once bool
	// before is a reply to the question that the validator validates first: what it leaves in the
	// validator's cache of zones must not change the status of msg.
	before *dns.Msg
	// qname is the query name as the case spells it, if not as question does.
	qname string
	// The validator has the keys of the zones anchors as trust anchors beside that of the root,
	// and the NSEC3 iteration limit, if it is not zero.
	anchors []string
	limit   uint
}

type uniResult struct {
	id            string
	status        ValidationResult
	verifications int64  // the signature verifications of the validation
	hashes        int64  // its NSEC3 hash computations
	broken        string // how the status breaks the oracle (see judge), or empty
	ranOut        bool   // the validation ran out of budget
	// For the honest reply to a question: the same for a validator that has no zone in its cache
	// yet, which is the most that the reply costs
	honest                        bool
	coldVerifications, coldHashes int64
}

// uniClock is a validator's cache of zones with a clock that stands still unless a case moves it,
// so that a case can say what the validator still knows after some time: an entry is gone once
// its lifetime has passed on that clock.
type uniClock struct {
	now     time.Duration
	entries map[string]uniClockEntry
}

type uniClockEntry struct {
	status  *zoneStatus
	expires time.Duration
}

func (c *uniClock) Put(key string, status *zoneStatus, ttl time.Duration) {
	if ttl > 0 {
		c.entries[key] = uniClockEntry{status, c.now + ttl}
	}
}

func (c *uniClock) Get(key string) (*zoneStatus, time.Duration) {
	entry := c.entries[key]

	return entry.status, max(entry.expires-c.now, 0)
}

func (c *uniClock) TotalCount() int { return len(c.entries) }

func (c *uniClock) Clear() { clear(c.entries) }

type uniUpstream func(ctx context.Context, request *model.Request) (*model.Response, error)

func (f uniUpstream) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	return f(ctx, request)
}

// validator returns a new validator for c, with blocky's default limits unless c has its own. Its
// queries get the honest reply, or the one in c.sub; asked, if not nil, collects them.
func (u *universe) validator(ctx context.Context, c uniCase, asked *[]string) *Validator {
	keys := make([]string, 0, 1+len(c.anchors))
	for _, zone := range append([]string{"."}, c.anchors...) {
		keys = append(keys, u.zone(zone).keys[0].String())
	}

	anchors, err := NewTrustAnchorStore(keys)
	Expect(err).Should(Succeed())

	upstream := func(_ context.Context, request *model.Request) (*model.Response, error) {
		id := uniID(request.Req.Question[0].Name, request.Req.Question[0].Qtype)
		if asked != nil && !slices.Contains(*asked, id) {
			*asked = append(*asked, id)
		}

		m, replaced := c.sub[id]
		if !replaced {
			m = u.reply(id).msg
		} else if c.once {
			delete(c.sub, id)
		}

		if m == nil {
			return nil, errors.New("upstream unreachable")
		}

		return &model.Response{Res: m.Copy()}, nil
	}

	return NewValidator(ctx, anchors, u.logger, uniUpstream(upstream), 1, 10, c.limit, 30, 3600)
}

// run validates every case and judges its status: the honest reply to every question, the
// mutations of the replies to uniMutated and these replies to a query name in upper case (see
// respelt), the replies to uniSubMutated with each of the validator's own queries failing or
// mutated, and the curated cases.
func (u *universe) run(ctx context.Context) []uniResult {
	var results []uniResult

	// Honest replies and mutated ones share a validator each, with the cache of zones that honest
	// DS and DNSKEY replies fill; every other case gets a new one.
	shared, probes := u.validator(ctx, uniCase{}, nil), u.validator(ctx, uniCase{}, nil)
	for _, question := range u.questions() {
		truth := u.reply(question)

		r := u.judge(ctx, shared, uniCase{id: question, question: question, msg: truth.msg.Copy(), want: truth.status.String()})
		if r.broken == "" {
			r.broken = u.unearned(ctx, probes, question, truth)
		}

		_, cold := u.validator(ctx, uniCase{}, nil).validate(ctx, truth.msg.Copy(), uniQuestion(question))
		r.honest, r.coldVerifications, r.coldHashes = true, cold.verifications.Load(), cold.hashes.Load()
		r.ranOut = r.ranOut || cold.ranOut()

		results = append(results, r)
	}

	if u.prefix != "" {
		return results
	}

	mutant := func(id, question string, m uniMutant) uniCase {
		c := uniCase{id: id + "+" + m.name, question: question, msg: m.msg}
		if m.same {
			c.want = u.reply(question).status.String()
		}

		return c
	}

	shared = u.validator(ctx, uniCase{}, nil)
	for _, question := range uniMutated {
		for _, m := range u.mutations(question, u.reply(question).msg) {
			results = append(results, u.judge(ctx, shared, mutant(question, question, m)))
		}

		results = append(results, u.judge(ctx, shared, u.respelt(question)))
	}

	mutated := map[string]bool{}

	for _, question := range uniSubMutated {
		var asked []string

		u.validator(ctx, uniCase{}, &asked).ValidateResponse(ctx, u.reply(question).msg.Copy(), uniQuestion(question))

		for _, query := range asked {
			if mutated[query] {
				continue
			}

			mutated[query] = true
			mutants := append([]uniMutant{
				{"error", nil, false},
				{"servfail", &dns.Msg{Response: true, Rcode: dns.RcodeServerFailure}, false},
				{"empty", &dns.Msg{Response: true}, false},
				{"truncated", &dns.Msg{Response: true, Truncated: true}, false},
			}, u.mutations(query, u.reply(query).msg)...)

			for _, m := range mutants {
				c := mutant(question+"@"+query, question, m)
				c.msg, c.sub = u.reply(question).msg.Copy(), map[string]*dns.Msg{query: m.msg}
				results = append(results, u.judge(ctx, u.validator(ctx, c, nil), c))
			}
		}
	}

	for _, c := range u.curated() {
		results = append(results, u.judge(ctx, u.validator(ctx, c, nil), c))
	}

	return results
}

// unearned validates the honest reply truth with each NSEC or NSEC3 record that signed zones vouch
// for spoilt in turn: first with its RRSIG broken, then without the record and its RRSIG. The
// right status must hang on every record of the proof, so each of these replies is Bogus. It
// returns how the first that is not breaks the oracle, or nothing.
func (u *universe) unearned(ctx context.Context, v *Validator, question string, truth uniTruth) string {
	for i, rr := range truth.msg.Ns[:truth.proof] {
		sig, isSig := rr.(*dns.RRSIG)
		if !isSig || sig.TypeCovered != dns.TypeNSEC && sig.TypeCovered != dns.TypeNSEC3 {
			continue
		}

		broken, without := truth.msg.Copy(), truth.msg.Copy()
		broken.Ns[i] = uniFailing(rr, 1)[0]
		without.Ns = slices.DeleteFunc(without.Ns, func(rr dns.RR) bool {
			other, isSig := rr.(*dns.RRSIG)

			return rr.Header().Name == sig.Hdr.Name &&
				(rr.Header().Rrtype == sig.TypeCovered || isSig && other.TypeCovered == sig.TypeCovered)
		})

		for _, probe := range []*dns.Msg{broken, without} {
			if got := v.ValidateResponse(ctx, probe, uniQuestion(question)); got == ValidationResultIndeterminate {
				return "indeterminate"
			} else if got != ValidationResultBogus {
				return "unearned"
			}
		}
	}

	return ""
}

// judge validates the reply of c with v and applies the oracle. The honest reply to the question
// is the truth: its status, its rcode and its answer section, the chain from the query name. A
// status breaks the oracle in one of these ways, which the status file records:
//   - indeterminate: the trust anchor encloses every name;
//   - false-bogus, false-insecure, false-secure: not the status that c wants or, if it wants none,
//     Insecure where the truth is Secure, or Secure where it is Insecure;
//   - not-chain: served (that is, not Bogus) with an answer section that is not the true one or,
//     if Insecure, lacks what signed zones vouch for of it;
//   - rcode: Secure with another rcode than the true one;
//   - unproven: served without an NSEC or NSEC3 record that signed zones vouch for in the honest
//     reply, which holds no more of them than the proof needs;
//   - unauthentic: Secure with an RRset that is not authentic, or Insecure with one that a signed
//     zone would have to sign and did not;
//   - unearned (see there): the right status for an honest reply, but not Bogus for that reply
//     with a record of its proof spoilt.
func (u *universe) judge(ctx context.Context, v *Validator, c uniCase) uniResult {
	q := uniQuestion(c.question)
	truth := u.reply(c.question, c.anchors...)

	if c.qname != "" {
		q.Name = c.qname
	}

	if c.once {
		clock := &uniClock{entries: map[string]uniClockEntry{}}
		v.validationCache = clock

		v.ValidateResponse(ctx, c.msg.Copy(), q)
		clock.now += BogusTTL + time.Second
	}

	if c.before != nil {
		v.ValidateResponse(ctx, c.before, q)
	}

	got, spent := v.validate(ctx, c.msg, q)
	result := uniResult{
		id: u.prefix + c.id, status: got, verifications: spent.verifications.Load(), hashes: spent.hashes.Load(),
		ranOut: spent.ranOut(),
	}

	answer, proof := truth.msg.Answer, truth.msg.Ns
	if got != ValidationResultSecure {
		answer, proof = answer[:truth.answer], proof[:truth.proof]
	}

	isData := func(rr dns.RR) bool { return rr.Header().Rrtype != dns.TypeRRSIG }
	isDenial := func(rr dns.RR) bool { return rr.Header().Rrtype == dns.TypeNSEC || rr.Header().Rrtype == dns.TypeNSEC3 }
	lacks := func(have, want []dns.RR, keep func(dns.RR) bool) bool {
		lines := uniLines(have, keep)

		return slices.ContainsFunc(uniLines(want, keep), func(line string) bool { return !slices.Contains(lines, line) })
	}

	switch {
	case got == ValidationResultIndeterminate:
		result.broken = "indeterminate"
	case c.want != "" && !slices.Contains(strings.Split(c.want, "|"), got.String()):
		result.broken = "false-" + strings.ToLower(got.String())
	case c.want != "" || got == ValidationResultBogus:
	case got == ValidationResultInsecure && truth.status == ValidationResultSecure:
		result.broken = "false-insecure"
	case lacks(c.msg.Answer, answer, isData) || got == ValidationResultSecure && lacks(answer, c.msg.Answer, isData):
		result.broken = "not-chain"
	case got == ValidationResultSecure && c.msg.Rcode != truth.msg.Rcode:
		result.broken = "rcode"
	case got == ValidationResultSecure && truth.status != ValidationResultSecure:
		result.broken = "false-secure"
	case lacks(c.msg.Ns, proof, isDenial):
		result.broken = "unproven"
	case u.unauthentic(truth.msg, c, got == ValidationResultSecure):
		result.broken = "unauthentic"
	}

	return result
}

// unauthentic reports whether the answer or authority section of the reply of c holds an RRset
// that is not authentic: neither an RRset of truth nor a signed RRset of the universe, or without
// its RRSIG. Unless all is set, only RRsets of names that a signed zone holds count.
func (u *universe) unauthentic(truth *dns.Msg, c uniCase, all bool) bool {
	own := map[string]string{} // text of an RRset of truth → text of its RRSIG, empty if it has none
	for _, p := range uniParts(truth) {
		own[uniText(p.rrs)] = uniText(p.sigs)
	}

	for _, p := range uniParts(c.msg) {
		if len(p.rrs) == 0 {
			continue
		}

		owner := strings.ToLower(p.rrs[0].Header().Name)
		z := u.zoneOf(owner, p.rrs[0].Header().Rrtype)

		// Zones without a chain of trust vouch for nothing, and a name that an Opt-Out zone does not
		// have may be an insecure delegation.
		if !all && (!u.secure(z, c.anchors) || z.kind == uniOptOut && !z.exists(owner)) {
			continue
		}

		sig, found := own[uniText(p.rrs)]
		if !found {
			sig, found = u.pool[uniText(p.rrs)]
		}

		signed := slices.ContainsFunc(p.sigs, func(rr dns.RR) bool { return uniText([]dns.RR{rr}) == sig })
		if !found || sig != "" && !signed {
			return true
		}
	}

	return false
}

// curated returns the cases of known findings. Most are attacks, which must be Bogus: replies
// that somebody without the key of the zone can send, made of records that the zones really hold
// where that is enough.
func (u *universe) curated() []uniCase {
	var cases []uniCase

	nsec, nsec3, optout, rsa := u.zone("nsec."), u.zone("nsec3."), u.zone("optout."), u.zone("rsa.")
	add := func(want, id, question string, msg *dns.Msg, sub map[string]*dns.Msg) *uniCase {
		cases = append(cases, uniCase{id: id, question: question, msg: msg, want: want, sub: sub})

		return &cases[len(cases)-1]
	}
	attack := func(id, question string, msg *dns.Msg, sub map[string]*dns.Msg) *uniCase {
		return add("Bogus", id, question, msg, sub)
	}
	msg := func(rcode int, answer []dns.RR, authority ...[]dns.RR) *dns.Msg {
		return uniReply(&dns.Msg{Response: true, Rcode: rcode},
			uniPart{0, answer, nil}, uniPart{1, slices.Concat(authority...), nil})
	}
	honest := func(question string) *dns.Msg { return u.reply(question).msg.Copy() }
	// forged returns an A RRset that no zone holds.
	forged := func(name string) []dns.RR { return []dns.RR{uniRR(".", name+" A 203.0.113.66")} }
	wildcardA := func(z *uniZone, name string) []dns.RR {
		return z.signedAs(z.rrsets[uniJoin("*.wild", z.name)][dns.TypeA], name)
	}
	// resigned returns the NSEC3 of www.nsec3. as its zone would sign it after change.
	resigned := func(change func(*dns.NSEC3)) []dns.RR {
		denial := dns.Copy(nsec3.denials("www.nsec3.")[0]).(*dns.NSEC3)
		change(denial)
		denial.Hdr.Name = strings.ToLower(dns.HashName("www.nsec3.", dns.SHA1, denial.Iterations, "")) + ".nsec3."

		return nsec3.signer().signed([]dns.RR{denial})
	}

	const noError, nameError = dns.RcodeSuccess, dns.RcodeNameError

	// GHSA-583r: a forged answer in the signed zone sec.optout., whose DS RRset "is denied" by
	// Opt-Out NSEC3 records of optout.: the one that ends at the hash of sec.optout., the one that
	// covers the query name, and the delegation's own NSEC3 as closest encloser. The NSEC3 of a
	// delegation is no closest encloser for a name error below the zone cut either.
	at := slices.Index(optout.chain, optout.denials("sec.optout.")[0])
	before := optout.chain[(at+len(optout.chain)-1)%len(optout.chain)]
	attack("583r/ends-at-hash", "sec.optout./A", msg(noError, forged("sec.optout.")), map[string]*dns.Msg{
		"sec.optout./DS": msg(noError, nil, optout.soa(), optout.signed([]dns.RR{before})),
	})
	attack("583r/covers-qname", "www.sec.optout./A", msg(noError, forged("www.sec.optout.")), map[string]*dns.Msg{
		"www.sec.optout./DS": msg(noError, nil, optout.soa(), optout.denials("www.sec.optout.")),
	})
	attack("583r/delegation-encloser-ds", "www.sec.optout./A", msg(noError, forged("www.sec.optout.")), map[string]*dns.Msg{
		"www.sec.optout./DS": msg(noError, nil, optout.soa(), optout.denials("sec.optout.", "www.sec.optout.")),
	})
	attack("583r/delegation-encloser-nxdomain", "www.sec.nsec3./A",
		msg(nameError, nil, nsec3.soa(), nsec3.denials("sec.nsec3.", "www.sec.nsec3.", "*.sec.nsec3.")), nil)

	// GHSA-g35c: signatures that name keys with the exponent 2^32+1 and do not verify.
	keys := uniParts(honest("rsa./DNSKEY"))[0]
	attack("g35c/dnskey-bad-sig", "www.rsa./A", honest("www.rsa./A"), map[string]*dns.Msg{
		"rsa./DNSKEY": msg(noError, slices.Concat(keys.rrs, uniFailing(keys.sigs[0], 1))),
	})
	attack("g35c/unverifiable-rrsig", "www.rsa./A",
		msg(noError, append(forged("www.rsa."), uniJunk("www.rsa.", dns.TypeA, rsa.keys[1].DNSKEY))), nil)

	// GHSA-vgm3: work without bound. Nine RRSIGs fail before the one that verifies, or eight for
	// an RRset whose owner name is spelt in three ways: giving up is right. What a key with an
	// exponent of 4096 bits gets is policy. Not using it leaves no path to its zone, as with a DS
	// RRset of algorithms that the validator lacks (RFC 4035 §5.2): Insecure. Unbound, whose
	// OpenSSL does not load such a key, fails the signature: Bogus.
	www := uniParts(honest("www.nsec./A"))[0]
	spelt := slices.Concat(www.rrs, uniOwned(www.rrs, strings.ToUpper), uniOwned(www.rrs, func(string) string { return "Www.nsec." }))
	attack("vgm3/nine-rrsigs", "www.nsec./A", msg(noError, slices.Concat(www.rrs, uniFailing(www.sigs[0], 9), www.sigs)), nil)
	attack("vgm3/case-variants", "www.nsec./A", msg(noError, slices.Concat(spelt, uniFailing(www.sigs[0], 8), www.sigs)), nil)
	add("Insecure|Bogus", "vgm3/exponent-4096", "www.exp4096./A", honest("www.exp4096./A"), nil)

	// GHSA-6fgw: denials from a zone that does not hold the name. other. signs an NSEC3 named after
	// the hash of sec.nsec3.; the one NSEC of one. covers every other name; an unsigned NSEC stands
	// beside a signed SOA; the NSEC and NSEC3 of a delegation deny names at and below the zone cut.
	foreign := []dns.RR{&dns.NSEC3{
		Hdr:  uniHdr(strings.ToLower(dns.HashName("sec.nsec3.", dns.SHA1, 0, ""))+".other.", dns.TypeNSEC3),
		Hash: dns.SHA1, HashLength: sha1.Size, NextDomain: dns.HashName("other.", dns.SHA1, 0, ""),
		TypeBitMap: []uint16{dns.TypeNS},
	}}
	attack("6fgw/other-nsec3-ds", "sec.nsec3./A", msg(noError, forged("sec.nsec3.")), map[string]*dns.Msg{
		"sec.nsec3./DS": msg(noError, nil, u.zone("other.").signer().signed(foreign)),
	})
	attack("6fgw/other-zone-nsec", "www.sec.nsec./A", msg(nameError, nil, u.zone("one.").denials("one.")), nil)
	attack("6fgw/unsigned-nsec", "www.nsec./A",
		msg(nameError, nil, nsec.soa(), []dns.RR{uniRR(".", "a.insecure.nsec. NSEC zz.nsec. A")}), nil)
	attack("6fgw/cut-nsec-nodata", "sec.nsec./A", msg(noError, nil, nsec.soa(), nsec.denials("sec.nsec.")), nil)
	attack("6fgw/cut-nsec-nxdomain", "www.sec.nsec./A", msg(nameError, nil, nsec.soa(), nsec.denials("sec.nsec.")), nil)
	attack("6fgw/cut-nsec3-nodata", "sec.nsec3./TXT", msg(noError, nil, nsec3.soa(), nsec3.denials("sec.nsec3.")), nil)

	// The same from zones that are not above the name. The last NSEC of a zone covers, in the order
	// of names, what is after its owner name and what is before its apex: names of a sibling zone,
	// and the names above the apex. And the NSEC or NSEC3 of a zone apex does not deny the DS RRset
	// of that name, which the zone above holds.
	below, apexNSEC, apexNSEC3 := u.zone("f.e.d.c.b.deep."), u.zone("sec.nsec3."), u.zone("sec.nsec.")
	attack("6fgw/sibling-zone-nsec", "nx.twin./A", msg(nameError, nil, u.zone("deep.").denials("zz.deep.")), nil)
	attack("6fgw/zone-below-nsec", "e.d.c.b.deep./A", msg(nameError, nil, below.denials("zz.f.e.d.c.b.deep.")), nil)
	attack("6fgw/apex-nsec-ds", "sec.nsec3./DS", msg(noError, nil, apexNSEC.soa(), apexNSEC.denials("sec.nsec3.")), nil)
	attack("6fgw/apex-nsec3-ds", "sec.nsec./DS", msg(noError, nil, apexNSEC3.soa(), apexNSEC3.denials("sec.nsec.")), nil)

	// GHSA-mv8x: wildcard proofs. host.wild exists beside *.wild and has a TXT RRset only.
	reowned := uniOwned(nsec.denials("*.wild.nsec."), func(string) string { return "m.wild.nsec." })
	attack("mv8x/no-proof", "host.wild.nsec./A", msg(noError, wildcardA(nsec, "host.wild.nsec.")), nil)
	attack("mv8x/unsigned-proof", "host.wild.nsec./A",
		msg(noError, wildcardA(nsec, "host.wild.nsec."), []dns.RR{uniRR(".", "a.wild.nsec. NSEC z.wild.nsec. A")}), nil)
	attack("mv8x/full-name-cover", "a.host.wild.nsec3./A",
		msg(noError, wildcardA(nsec3, "a.host.wild.nsec3."), nsec3.denials("a.host.wild.nsec3.")), nil)
	attack("mv8x/nodata-no-next-closer", "host.wild.nsec3./TXT",
		msg(noError, nil, nsec3.soa(), nsec3.denials("wild.nsec3.", "*.wild.nsec3.")), nil)
	attack("mv8x/no-wildcard-denial", "x.wild.nsec./A", msg(nameError, nil, nsec.soa(), nsec.denials("x.wild.nsec.")), nil)
	attack("mv8x/reowned-nsec", "www.nsec./A", msg(nameError, nil, nsec.soa(), nsec.denials("host.wild.nsec."), reowned), nil)
	attack("mv8x/reowned-nsec-nodata", "host.wild.nsec./TXT", msg(noError, nil, nsec.soa(),
		uniOwned(nsec.denials("*.wild.nsec."), func(string) string { return "host.wild.nsec." })), nil)

	// The NSEC3 "no data" proof of a wildcard without a cover of the next closer name, across a zone
	// cut: what nsec3. signs if it holds *.nsec3. with an A RRset only, beside the NSEC3 of its
	// apex, as the denial of www.sec.nsec3./TXT. That name is in the zone below the delegation
	// sec.nsec3., whose NSEC3 the reply leaves out. Nothing covers the hash of a name that has a
	// record, so the cover of the next closer name is what such a reply cannot hold: the NSEC3 of
	// the wildcard ends at the hash that follows its own in the chain of the zone.
	apexWildcard := func(types ...uint16) []dns.RR {
		return nsec3.signer().signed([]dns.RR{&dns.NSEC3{
			Hdr:  uniHdr(strings.ToLower(dns.HashName("*.nsec3.", dns.SHA1, 0, ""))+".nsec3.", dns.TypeNSEC3),
			Hash: dns.SHA1, HashLength: sha1.Size, NextDomain: nsec3.denials("*.nsec3.")[0].(*dns.NSEC3).NextDomain,
			TypeBitMap: types,
		}})
	}
	attack("mv8x/nodata-below-zone-cut", "www.sec.nsec3./TXT",
		msg(noError, nil, nsec3.soa(), nsec3.denials("nsec3."), apexWildcard(dns.TypeA, dns.TypeRRSIG)), nil)

	// The NSEC3 of a wildcard with an NS RRset as the denial of the DS RRset of a secure
	// delegation: what nsec3. signs if it holds *.nsec3. NS, beside the NSEC3 of its apex, as the
	// reply to the DS query for sec.nsec3., which leaves out the NSEC3 of that delegation. A
	// wildcard is no delegation (RFC 5155 §8.6, §8.9), so the zone below stays what it is and a
	// forged answer in it is refused.
	attack("D-C25/wildcard-ns-ds", "sec.nsec3./A", msg(noError, forged("sec.nsec3.")), map[string]*dns.Msg{
		"sec.nsec3./DS": msg(noError, nil, nsec3.soa(), nsec3.denials("nsec3."), apexWildcard(dns.TypeNS)),
	})

	// GHSA-8mfq: parts of a reply that nothing proves.
	junk := []dns.RR{uniJunk("www.nsec.", dns.TypeA, nsec.signer().DNSKEY)}
	alias := nsec.signed(nsec.rrsets["alias.nsec."][dns.TypeCNAME])
	attack("8mfq/unsigned-beside-soa", "www.nsec./A", msg(noError, forged("www.nsec."), nsec.soa()), nil)
	attack("8mfq/rrsig-in-additional", "www.nsec./A", msg(noError, forged("www.nsec.")), nil).msg.Extra = junk
	attack("8mfq/nxdomain-no-proof", "www.nsec./A", msg(nameError, nil, nsec.soa()), nil)
	attack("8mfq/nodata-no-proof", "www.nsec./A", msg(noError, nil, nsec.soa()), nil)
	attack("8mfq/rrsig-only", "www.nsec./A", msg(noError, junk), nil)
	attack("8mfq/cname-to-nx", "alias.nsec./A", msg(nameError, alias, nsec3.soa()), nil)
	attack("8mfq/cname-to-nodata", "alias.nsec./A", msg(noError, alias, nsec3.soa()), nil)
	attack("8mfq/forged-authority", "www.nsec./A", msg(noError, slices.Concat(www.rrs, www.sigs),
		nsec.soa()[:1], []dns.RR{uniJunk("nsec.", dns.TypeSOA, nsec.signer().DNSKEY)}), nil)

	// Findings of the audits. An answer that is not the chain from the query name, an rcode that
	// contradicts the answer, a forged record of a signed zone behind an unsigned CNAME, NODATA
	// "proven" by the NSEC or NSEC3 of a CNAME, and a chain that an empty DS reply leaves
	// unfinished.
	attack("R13/other-name", "www.nsec./A", honest("a.ent.nsec./A"), nil)
	attack("R13/other-type", "www.nsec./A", honest("www.nsec./TXT"), nil)
	attack("R13/broken-chain", "alias.nsec./A", msg(noError, slices.Concat(alias, honest("a.ent.nsec3./A").Answer)), nil)
	attack("R14/nx-with-answer", "www.nsec./A", msg(nameError, slices.Concat(www.rrs, www.sigs)), nil)
	attack("C13/unsigned-cname-into-signed", "back.insecure.nsec./A",
		msg(noError, slices.Concat(honest("back.insecure.nsec./CNAME").Answer, forged("www.nsec."))), nil)
	attack("R16/nsec-cname-bit", "alias.nsec./A", msg(noError, nil, nsec.soa(), nsec.denials("alias.nsec.")), nil)
	attack("R16/nsec3-cname-bit", "chain.nsec3./A", msg(noError, nil, nsec3.soa(), nsec3.denials("chain.nsec3.")), nil)
	attack("R16/wildcard-cname-bit", "x.cwild.nsec3./A",
		msg(noError, nil, nsec3.soa(), nsec3.denials("cwild.nsec3.", "x.cwild.nsec3.", "*.cwild.nsec3.")), nil)

	unfinished := uniJunk("www.nsec.", dns.TypeA, nsec.signer().DNSKEY)
	unfinished.SignerName = "www.nsec."
	attack("R32/empty-ds", "www.nsec./A", msg(noError, append(forged("www.nsec."), unfinished)), map[string]*dns.Msg{
		"www.nsec./DS": {Response: true},
	})

	// A DS RRset, forged or the real one, signed by the child zone. A key without the Zone Key flag
	// that signs an answer and the DS RRset of a zone that does not exist, for a key of the
	// attacker's.
	child := u.zone("sec.nsec.").signer()
	selfSigned := []dns.RR{uniRR(".", "sec.nsec. DS 1 15 2 "+strings.Repeat("00", sha256.Size))}
	realDS := uniParts(honest("sec.nsec./DS"))[0].rrs
	evil := uniEd25519Key("evil.rsa.", 257, "evil.rsa., the attacker's")
	evilDS, evilA := []dns.RR{evil.ToDS(dns.SHA256)}, forged("www.evil.rsa.")
	attack("B3/ds-self-signed", "sec.nsec./DS", msg(noError, child.signed(selfSigned)), nil)
	attack("B3/real-ds-self-signed", "sec.nsec./DS", msg(noError, child.signed(realDS)), nil)
	attack("B3/ds-sub-reply-self-signed", "www.sec.nsec./A", honest("www.sec.nsec./A"), map[string]*dns.Msg{
		"sec.nsec./DS": msg(noError, child.signed(realDS)),
	})
	attack("A1/nonzone-bigexp", "www.rsa./A", msg(noError, rsa.keys[2].signed(forged("www.rsa."))), nil)
	attack("A1/nonzone-bigexp-ds", "www.evil.rsa./A", msg(noError, evil.signed(evilA)), map[string]*dns.Msg{
		"evil.rsa./DS":     msg(noError, rsa.keys[2].signed(evilDS)),
		"evil.rsa./DNSKEY": msg(noError, evil.signed([]dns.RR{evil.DNSKEY})),
	})

	// DS and DNSKEY replies for other. with the records of another delegation of the root, which
	// signs every DS RRset here. The DS RRset of one. with one more record, the digest of a key
	// under the name other. that is no key of that zone, beside that key as the DNSKEY RRset of
	// other. The DS RRset of rsa. for its RSA/SHA-1 key, which nothing verifies with, beside the
	// DNSKEY RRset of rsa. And a DS RRset of other. itself that names that key of rsa., by its
	// digest under the name rsa., beside the DNSKEY RRset of rsa.
	root, stray := u.zones[0].signer(), uniEd25519Key("other.", 257, "other., not a key of the zone")
	strayDS, unusableDS := stray.ToDS(dns.SHA256), rsa.keys[1].ToDS(dns.SHA256)
	strayDS.Hdr.Name = "one."
	misnamedDS := uniOwned([]dns.RR{unusableDS}, func(string) string { return "other." })
	attack("rfc7/ds-of-sibling-digest-of-target", "www.other./A", msg(noError, stray.signed(forged("www.other."))),
		map[string]*dns.Msg{
			"other./DS":     msg(noError, root.signed(append(uniParts(honest("one./DS"))[0].rrs, strayDS))),
			"other./DNSKEY": msg(noError, stray.signed([]dns.RR{stray.DNSKEY})),
		})
	attack("rfc7/ds-of-sibling-unusable-key", "www.other./A", msg(noError, forged("www.other.")), map[string]*dns.Msg{
		"other./DS": msg(noError, root.signed([]dns.RR{unusableDS})), "other./DNSKEY": honest("rsa./DNSKEY"),
	})
	attack("rfc7/dnskey-of-sibling-unusable-key", "www.other./A", msg(noError, forged("www.other.")), map[string]*dns.Msg{
		"other./DS": msg(noError, root.signed(misnamedDS)), "other./DNSKEY": honest("rsa./DNSKEY"),
	})

	// A DS RRset that nsec. signs for the wildcard *.nsec., as the reply to the DS query for
	// sec.nsec.: its RRSIG verifies it under that name too. It holds the digest of a key under the
	// name sec.nsec. that is no key of that zone, and the DNSKEY reply holds that key.
	planted := uniEd25519Key("sec.nsec.", 257, "sec.nsec., not a key of the zone")
	plantedDS := planted.ToDS(dns.SHA256)
	plantedDS.Hdr.Name = "*.nsec."
	expandedDS := uniOwned(nsec.signer().signed([]dns.RR{plantedDS}), func(string) string { return "sec.nsec." })
	attack("rfc7/ds-of-wildcard", "www.sec.nsec./A", msg(noError, planted.signed(forged("www.sec.nsec."))),
		map[string]*dns.Msg{
			"sec.nsec./DS":     msg(noError, expandedDS),
			"sec.nsec./DNSKEY": msg(noError, planted.signed([]dns.RR{planted.DNSKEY})),
		})

	// The same DS RRset as the reply to a client that asks for the DS RRset of sec.nsec.: a
	// wildcard gives no name a DS RRset (RFC 4592 §4.6)
	attack("rfc7/ds-of-wildcard-asked", "sec.nsec./DS", msg(noError, expandedDS), nil)

	// The DNSKEY RRset of a zone signed by its zone-signing key only, and that of the root without
	// an RRSIG and without the zone-signing key, in one reply: it must not serve as the keys of
	// the root for the validations that follow.
	rootKeys, zoneKeys := u.zones[0].rrsets["."][dns.TypeDNSKEY], nsec3.rrsets["nsec3."][dns.TypeDNSKEY]
	add("Secure", "B-C4/anchored-key-only", "www.nsec./A", honest("www.nsec./A"), map[string]*dns.Msg{
		"./DNSKEY": msg(noError, rootKeys[:1]),
	}).once = true
	attack("keys/dnskey-signed-by-zsk", "www.nsec3./A", honest("www.nsec3./A"), map[string]*dns.Msg{
		"nsec3./DNSKEY": msg(noError, nsec3.signer().signed(zoneKeys)),
	})

	// The key of island.unsigned.optout. as a second trust anchor: optout., a zone above it, can
	// no longer make its names Insecure, neither in a DS reply nor in the reply itself.
	island := []string{"island.unsigned.optout."}
	above := slices.Concat(optout.soa(), optout.denials("optout.", "unsigned.optout.", "*.optout."))
	add("Secure", "B-C2/anchor-below-insecure", "www.island.unsigned.optout./A",
		honest("www.island.unsigned.optout./A"), nil).anchors = island
	attack("B-C2/ds-denied-above-anchor", "www.island.unsigned.optout./A",
		msg(noError, forged("www.island.unsigned.optout.")), map[string]*dns.Msg{
			"www.island.unsigned.optout./DS": msg(nameError, nil, above),
		}).anchors = island
	attack("B-C2/nxdomain-above-anchor", "nx.island.unsigned.optout./A", msg(nameError, nil, above), nil).anchors = island

	// The key of sec.nsec. as a second trust anchor: what sec.nsec. holds is authenticated through
	// that anchor, so an RRSIG of nsec., the secure zone above it, verifies no record of a name of
	// sec.nsec. The DS RRset of sec.nsec. is a record of nsec., which signs it.
	anchored := []string{"sec.nsec."}
	attack("B-C14/signed-above-anchor", "www.sec.nsec./A",
		msg(noError, nsec.signer().signed(forged("www.sec.nsec."))), nil).anchors = anchored
	add("Secure", "B-C14/ds-of-anchored-zone", "sec.nsec./DS", honest("sec.nsec./DS"), nil).anchors = anchored

	// An NSEC of odd. that covers a name of the zone only in the order of zone file text.
	attack("D-B1/escaped-octets", `caf\195\169.odd./A`,
		msg(nameError, nil, u.zone("odd.").soa(), u.zone("odd.").denials("caa.odd.", "odd.")), nil)

	// No attacks, but what a zone may sign itself. An NSEC3 with a flag that is not defined is
	// ignored (RFC 5155 §8.2), which leaves the reply without proof. For one with more iterations
	// than the limit, RFC 9276 §3.2 allows Insecure as well as a failure. A limit above 65535
	// allows every count.
	add("Bogus", "D-C2/undefined-nsec3-flag", "www.nsec3./TXT",
		msg(noError, nil, nsec3.soa(), resigned(func(denial *dns.NSEC3) { denial.Flags = 2 })), nil)
	add("Insecure|Bogus", "D-C5/iterations-above-limit", "www.nsec3./TXT",
		msg(noError, nil, nsec3.soa(), resigned(func(denial *dns.NSEC3) { denial.Iterations = 151 })), nil)
	add("Secure", "D-C5/limit-above-65535", "www.nsec3./TXT",
		msg(noError, nil, nsec3.soa(), resigned(func(denial *dns.NSEC3) { denial.Iterations = 1 })), nil).limit = 65536

	// Not an attack: the honest reply for a name of the insecure zone insecure.nsec., after a reply
	// with an RRSIG that names the zone as its signer in upper case (RFC 4343). The walk to that
	// signer must leave the validator with the zone as it is.
	upperSigner := uniJunk("www.insecure.nsec.", dns.TypeA, nsec.signer().DNSKEY)
	upperSigner.SignerName = "INSECURE.NSEC."
	add("Insecure", "R50/honest-after-upper-case-signer", "www.insecure.nsec./A", honest("www.insecure.nsec./A"), nil).
		before = msg(noError, append(uniParts(honest("www.insecure.nsec./A"))[0].rrs, upperSigner))

	// Not an attack: what nsec3. sends if it holds *.fake.nsec3. CNAME www.nsec., for a name that
	// the wildcard matches and a type that www.nsec. lacks. The reply proves the expansion with an
	// NSEC3 record of nsec3. and the end of the chain with an NSEC record of nsec.: each proof must
	// be read from the records of its own zone.
	expanded := uniOwned(nsec3.signer().signed([]dns.RR{uniRR(".", "*.fake.nsec3. CNAME www.nsec.")}),
		func(string) string { return "x.fake.nsec3." })
	add("Secure", "zones/nsec3-wildcard-cname-into-nsec-zone", "x.fake.nsec3./AAAA",
		msg(noError, expanded, nsec3.denials("x.fake.nsec3."), honest("www.nsec./AAAA").Ns), nil)

	// Not an attack: what nsec3. sends if it holds *.fake.nsec3. CNAME nx.other., for a name that
	// the wildcard matches, and what other. sends for the name error if its NSEC3 chain has a salt
	// and holds its apex alone. The NSEC3 records of the two zones differ in their parameters, and
	// each proof is read from those of its own zone.
	apexAlone := dns.HashName("other.", dns.SHA1, 0, "ab")
	salted := []dns.RR{&dns.NSEC3{
		Hdr:  uniHdr(strings.ToLower(apexAlone)+".other.", dns.TypeNSEC3),
		Hash: dns.SHA1, SaltLength: 1, Salt: "ab", HashLength: sha1.Size, NextDomain: apexAlone,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM},
	}}
	gone := uniOwned(nsec3.signer().signed([]dns.RR{uniRR(".", "*.fake.nsec3. CNAME nx.other.")}),
		func(string) string { return "x.fake.nsec3." })
	add("Secure", "zones/nsec3-wildcard-cname-into-nsec3-zone", "x.fake.nsec3./A", msg(nameError, gone,
		nsec3.denials("x.fake.nsec3."), u.zone("other.").soa(), u.zone("other.").signer().signed(salted)), nil)

	// Not an attack: what nsec. sends if it holds *.nsec. CNAME www.unsigned.optout., for a name
	// that the wildcard matches and a type that the target lacks. The last NSEC record of nsec.
	// proves the expansion. In the order of names it also covers the target, which is a name of a
	// zone that nothing signs: the answer has the status of that zone.
	out := uniOwned(nsec.signer().signed([]dns.RR{uniRR(".", "*.nsec. CNAME www.unsigned.optout.")}),
		func(string) string { return "zz.nsec." })
	add("Insecure", "zones/nsec-wildcard-cname-into-unsigned-zone", "zz.nsec./TXT", msg(noError, out,
		u.zone("unsigned.optout.").rrsets["unsigned.optout."][dns.TypeSOA], nsec.denials("zz.nsec.")), nil)

	// Not attacks on a signed zone, but replies that no zone sends: a name error or "no data" for a
	// name of an insecure zone with records of the signed zone above it, the NSEC or NSEC3 record of
	// the delegation among them, or its Opt-Out proof. Whatever these records are, they are not
	// those of the zone that holds the name, which stays what it is: Insecure.
	add("Insecure", "zones/insecure-child-nxdomain-parent-nsec", "nx.insecure.nsec./A",
		msg(nameError, nil, nsec.soa(), nsec.denials("nsec.", "insecure.nsec.", "zz.nsec.")), nil)
	add("Insecure", "zones/insecure-child-nodata-parent-nsec", "insecure.nsec./A",
		msg(noError, nil, nsec.soa(), nsec.denials("nsec.", "insecure.nsec.")), nil)
	add("Insecure", "zones/insecure-child-nxdomain-parent-nsec3", "nx.insecure.nsec3./A",
		msg(nameError, nil, nsec3.soa(), nsec3.denials("nsec3.", "insecure.nsec3.", "*.nsec3.")), nil)
	add("Insecure", "zones/insecure-child-nxdomain-parent-optout", "nx.unsigned.optout./A", msg(nameError, nil, above), nil)

	// Not attacks: the honest proof of a name error in a signed zone, after records of the signed
	// zone above it that the reply does not need. The records of the zone that holds the name
	// decide, whichever kind either zone has.
	add("Secure", "zones/child-nsec-beside-parent-nsec3", "nx.sec.nsec3./A", msg(nameError, nil,
		nsec3.denials("nsec3.", "sec.nsec3.", "*.nsec3."), honest("nx.sec.nsec3./A").Ns), nil)
	add("Secure", "zones/child-nsec3-beside-parent-nsec", "nx.sec.nsec./A", msg(nameError, nil,
		nsec.denials("nsec.", "sec.nsec."), honest("nx.sec.nsec./A").Ns), nil)

	// Not an attack: an unsigned NS RRset, as forwarders add it to the authority section, beside a
	// complete proof.
	add("Secure", "R24/unsigned-ns", "nx.nsec./A",
		msg(nameError, nil, honest("nx.nsec./A").Ns, u.zones[0].rrsets["nsec."][dns.TypeNS]), nil)

	// A DS question at a name that owns a CNAME RRset, answered with that RRset and nothing else,
	// as some resolvers do. The name is no zone cut and has no other data, so the RRset is the
	// whole answer and the reply has its status, whatever the target is: a name of a signed zone
	// without DS RRset, or a name of an unsigned zone. Only a DS question ends so.
	toInsecure := nsec.signed(nsec.rrsets["to-insecure.nsec."][dns.TypeCNAME])
	back := honest("back.insecure.nsec./CNAME").Answer
	add("Secure", "cname-ds/alone", "alias.nsec./DS", msg(noError, alias), nil)
	add("Secure", "cname-ds/alone-to-unsigned-zone", "to-insecure.nsec./DS", msg(noError, toInsecure), nil)
	add("Insecure", "cname-ds/alone-in-unsigned-zone", "back.insecure.nsec./DS", msg(noError, back), nil)
	attack("cname-ds/alone-without-rrsig", "alias.nsec./DS", msg(noError, alias[:1]), nil)
	attack("cname-ds/alone-for-another-type", "alias.nsec./A", msg(noError, alias), nil)

	// The zone above a name answers for its DS RRset, and so for the CNAME RRset in its place. A
	// CNAME RRset at the apex of sec.nsec., as that zone signs it, is no record of nsec., and
	// neither is one without RRSIG at insecure.nsec., a delegation that nsec. signs for.
	apexCNAME := u.zone("sec.nsec.").signer().signed([]dns.RR{uniRR(".", "sec.nsec. CNAME www.sec.nsec.")})
	attack("cname-ds/alone-signed-at-the-name", "sec.nsec./DS", msg(noError, apexCNAME), nil)
	attack("cname-ds/alone-at-insecure-delegation", "insecure.nsec./DS",
		msg(noError, []dns.RR{uniRR(".", "insecure.nsec. CNAME www.nsec.")}), nil)

	// The same question with a reply that goes on and does not prove what it says of the target: a
	// name error, the SOA RRset of the zone of the target, or a second CNAME RRset. And with the
	// CNAME RRset that a wildcard gives the name, alone and with the NSEC3 record that proves the
	// expansion: that reply holds a denial, so it does not end with its answer. The record that
	// covers y.cwild.nsec3. is that of a.ent.nsec3., which says nothing of the target www.nsec3.
	second := nsec3.signed(nsec3.rrsets["chain.nsec3."][dns.TypeCNAME])
	expandedCNAME := nsec3.signedAs(nsec3.rrsets["*.cwild.nsec3."][dns.TypeCNAME], "y.cwild.nsec3.")
	attack("cname-ds/name-error", "alias.nsec./DS", msg(nameError, alias), nil)
	attack("cname-ds/soa-without-denial", "alias.nsec./DS", msg(noError, alias, nsec3.soa()), nil)
	attack("cname-ds/second-cname", "chain.nsec./DS",
		msg(noError, slices.Concat(nsec.signed(nsec.rrsets["chain.nsec."][dns.TypeCNAME]), second)), nil)
	attack("cname-ds/wildcard-without-proof", "y.cwild.nsec3./DS", msg(noError, expandedCNAME), nil)
	attack("cname-ds/wildcard-with-proof-only", "y.cwild.nsec3./DS",
		msg(noError, expandedCNAME, nsec3.denials("y.cwild.nsec3.")), nil)

	return cases
}
