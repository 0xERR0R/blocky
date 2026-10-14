package dnssec

import (
	"context"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// emptyNonTerminalChain models the real-world `co.jp` situation (issue #2280):
//
//	jp.            <- signed zone, trust anchor
//	co.jp.         <- EMPTY NON-TERMINAL inside jp.: it is not a zone and has no
//	                  delegation. A DS query for it is answered by jp. with a signed
//	                  NSEC3 NODATA proof whose matching NSEC3 has NO NS bit (the name
//	                  is an ordinary in-zone name, not a delegation).
//	jprs.co.jp.    <- genuinely delegated SUBZONE of jp. (signed), DS published in jp.
//
// The walk of the chain of trust must not mistake the `co.jp` empty non-terminal for an
// unsigned delegation: doing so makes the DS-absence proof look Bogus and returns SERVFAIL
// for every signed name below `co.jp` (jprs.co.jp, soumu.go.jp, iij.ad.jp, ...).
func entChain(zone, ent, child string) (anchor string, fn func(context.Context, *model.Request) (*model.Response, error)) {
	zone = dns.Fqdn(zone)
	ent = dns.Fqdn(ent)
	child = dns.Fqdn(child)

	// The signed parent zone that owns both the ENT and the real delegation.
	zoneKey, zonePriv, anchorStr := newSignedZoneKey(zone)
	zoneDNSKEYSig := signRRset([]dns.RR{zoneKey}, dns.TypeDNSKEY, zoneKey, zonePriv, zone)

	// NSEC3 params used by the parent zone; owner hashes are the REAL dns.HashName values
	// so the matching NSEC3 for the ENT actually matches what checkDirectNSEC3Match computes.
	const (
		hashAlg    = dns.SHA1
		salt       = ""
		iterations = 0
	)
	entHash := dns.HashName(ent, hashAlg, iterations, salt)

	// Signed NSEC3 NODATA proof for the ENT's DS query: owner == hash(ent), type bitmap
	// WITHOUT NS (and without DS) => an in-zone empty non-terminal, NOT a delegation.
	entNSEC3 := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name: entHash + "." + zone, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300,
		},
		Hash:       hashAlg,
		Flags:      0,
		Iterations: iterations,
		SaltLength: uint8(len(salt)),
		Salt:       salt,
		HashLength: 20,
		NextDomain: dns.HashName("\000."+ent, hashAlg, iterations, salt),
		TypeBitMap: []uint16{dns.TypeRRSIG}, // no NS, no DS, no SOA
	}
	entNSEC3Sig := signRRset([]dns.RR{entNSEC3}, dns.TypeNSEC3, zoneKey, zonePriv, zone)

	// The genuine signed delegation below the zone (jprs.co.jp): DS in the zone, and the
	// child's own signed DNSKEY.
	childKey, childPriv, _ := newSignedZoneKey(child)
	childDNSKEYSig := signRRset([]dns.RR{childKey}, dns.TypeDNSKEY, childKey, childPriv, child)
	childDS := childKey.ToDS(dns.SHA256)
	childDSSig := signRRset([]dns.RR{childDS}, dns.TypeDS, zoneKey, zonePriv, zone)

	// A genuine unsigned delegation below the same parent: matching NSEC3 with NS set, DS clear.
	unsigned := dns.Fqdn("unsigned." + ent)
	unsignedHash := dns.HashName(unsigned, hashAlg, iterations, salt)
	unsignedNSEC3 := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name: unsignedHash + "." + zone, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300,
		},
		Hash:       hashAlg,
		Flags:      0,
		Iterations: iterations,
		SaltLength: uint8(len(salt)),
		Salt:       salt,
		HashLength: 20,
		NextDomain: dns.HashName("\000."+unsigned, hashAlg, iterations, salt),
		TypeBitMap: []uint16{dns.TypeNS}, // NS delegation, DS absent
	}
	unsignedNSEC3Sig := signRRset([]dns.RR{unsignedNSEC3}, dns.TypeNSEC3, zoneKey, zonePriv, zone)

	fn = func(_ context.Context, req *model.Request) (*model.Response, error) {
		q := req.Req.Question[0]
		name := dns.Fqdn(q.Name)

		switch {
		case q.Qtype == dns.TypeDS && name == unsigned:
			return &model.Response{Res: &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Ns:     []dns.RR{unsignedNSEC3, unsignedNSEC3Sig},
			}}, nil
		case q.Qtype == dns.TypeDS && name == ent:
			// jp. proves the ENT's DS does not exist with an NSEC3 NODATA (no NS bit).
			return &model.Response{Res: &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Ns:     []dns.RR{entNSEC3, entNSEC3Sig},
			}}, nil
		case q.Qtype == dns.TypeDS && name == child:
			return &model.Response{Res: &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{childDS, childDSSig},
			}}, nil
		case q.Qtype == dns.TypeDNSKEY && name == zone:
			return &model.Response{Res: &dns.Msg{Answer: []dns.RR{zoneKey, zoneDNSKEYSig}}}, nil
		case q.Qtype == dns.TypeDNSKEY && name == child:
			return &model.Response{Res: &dns.Msg{Answer: []dns.RR{childKey, childDNSKEYSig}}}, nil
		default:
			return &model.Response{Res: &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}}, nil
		}
	}

	return anchorStr, fn
}

var _ = Describe("chain of trust across an empty non-terminal (#2280)", func() {
	var ctx context.Context

	BeforeEach(func(specCtx SpecContext) {
		ctx = specCtx
	})

	const (
		zone  = "jp."
		ent   = "co.jp."
		child = "jprs.co.jp."
	)

	It("walks past a non-delegation empty non-terminal and validates the real delegation below it", func() {
		// Regression: `co.jp` is an empty non-terminal inside `jp`, not a zone. The DS-absence
		// proof for it carries no NS bit (correct for an in-zone name), which must NOT be read
		// as Bogus. walkChainOfTrust must continue and validate the genuine `jprs.co.jp`
		// delegation, yielding Secure instead of SERVFAIL.
		anchor, fn := entChain(zone, ent, child)
		store, err := NewTrustAnchorStore([]string{anchor})
		Expect(err).Should(Succeed())

		mockUpstream := &mockResolver{ResolveFn: fn}
		logger, _ := log.NewMockEntry()
		v := NewValidator(ctx, store, logger, mockUpstream, 1, 10, 150, 30, 3600)
		budgetCtx := context.WithValue(ctx, queryBudgetKey{}, 30)

		Expect(v.walkChainOfTrust(budgetCtx, child)).Should(Equal(ValidationResultSecure),
			"a signed name delegated below an empty non-terminal (co.jp inside jp) must validate as Secure, not Bogus")
	})

	It("treats the empty non-terminal level as transparent, and a real unsigned delegation as Insecure", func() {
		// Two distinct outcomes must be preserved by the fix:
		//   * the empty non-terminal `co.jp` is NOT a zone cut -> transparent (Secure at this
		//     level), so the walk continues to the real delegation below it;
		//   * a genuine unsigned delegation (NS bit set, DS absent) must still resolve to
		//     Insecure and must NOT be misread as an in-zone name.
		anchor, fn := entChain(zone, ent, child)
		store, err := NewTrustAnchorStore([]string{anchor})
		Expect(err).Should(Succeed())

		mockUpstream := &mockResolver{ResolveFn: fn}
		logger, _ := log.NewMockEntry()
		v := NewValidator(ctx, store, logger, mockUpstream, 1, 10, 150, 30, 3600)
		budgetCtx := context.WithValue(ctx, queryBudgetKey{}, 30)

		Expect(v.validateDomainLevel(budgetCtx, ent)).Should(Equal(ValidationResultSecure),
			"an empty non-terminal is not a zone cut: its level must be transparent, not Bogus and not Insecure")

		// A real unsigned delegation under the same signed parent: an NSEC3 NODATA proof whose
		// matching record DOES assert a delegation (NS set, DS/SOA clear) is Insecure.
		Expect(v.validateDomainLevel(budgetCtx, "unsigned.co.jp.")).Should(Equal(ValidationResultInsecure),
			"a genuine NS-asserting delegation with DS absent must remain Insecure (unsigned), not transparent")

		// A DS absence with NO proof at all stays Indeterminate (cannot prove secure OR insecure) -
		// the relaxation applies only to an AUTHENTICATED in-zone DS-absence proof.
		Expect(v.validateDomainLevel(budgetCtx, "noproof.co.jp.")).Should(Equal(ValidationResultIndeterminate),
			"a DS absence with no authenticated NSEC/NSEC3 proof must remain Indeterminate")
	})
})
