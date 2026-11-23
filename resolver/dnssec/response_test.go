package dnssec

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The status of a reply is that of its answer: the worst of the statuses of the RRsets of the
// answer section, which must be the answer to the question, and of the proof for an answer that
// ends without data (RFC 4035 §5.4). Data without RRSIG is Insecure only below a proven insecure
// delegation, and Bogus anywhere else under a trust anchor (RFC 4035 §4.3). What the reply
// carries beside its answer must be authentic for the reply to be (RFC 4035 §3.2.3).
//
// example. is the trust anchor. It delegates signed.example. with a DS RRset and insecure.example.
// without one, which its NSEC record of that name proves.
var _ = Describe("Status of a reply", func() {
	const (
		parent   = "example."
		child    = "signed.example."
		insecure = "insecure.example."
	)

	var (
		ctx      context.Context
		chain    *signedChain
		upstream *mockResolver
		v        *Validator
		junk     *dns.RRSIG
	)

	newRR := func(s string) dns.RR {
		rr, err := dns.NewRR(s)
		Expect(err).Should(Succeed())

		return rr
	}
	// inParent and inChild return an RRset followed by the RRSIG that example. or signed.example.
	// makes for it
	inParent := func(rrset ...dns.RR) []dns.RR {
		sig := signRRset(rrset, rrset[0].Header().Rrtype, chain.parentKey, chain.parentPriv, parent)

		return append(slices.Clone(rrset), sig)
	}
	inChild := func(rrset ...dns.RR) []dns.RR {
		sig := signRRset(rrset, rrset[0].Header().Rrtype, chain.childKey, chain.childPriv, child)

		return append(slices.Clone(rrset), sig)
	}
	// expandedTo returns copies of rrs, a wildcard RRset with its RRSIG, as they answer for owner
	expandedTo := func(owner string, rrs []dns.RR) []dns.RR {
		expanded := make([]dns.RR, len(rrs))
		for i, rr := range rrs {
			expanded[i] = dns.Copy(rr)
			expanded[i].Header().Name = owner
		}

		return expanded
	}
	// badlySigned returns rrs, an RRset with its RRSIG, with the signature of the RRSIG replaced
	badlySigned := func(rrs []dns.RR) []dns.RR {
		bad := slices.Clone(rrs)
		sig, _ := dns.Copy(rrs[len(rrs)-1]).(*dns.RRSIG)
		sig.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
		bad[len(bad)-1] = sig

		return bad
	}
	soa := func(zone string) dns.RR {
		return newRR(zone + " 300 IN SOA ns." + zone + " hostmaster." + zone + " 1 3600 600 86400 300")
	}
	reply := func(rcode int, answer []dns.RR, authority ...[]dns.RR) *dns.Msg {
		return &dns.Msg{Rcode: rcode, Answer: answer, Ns: slices.Concat(authority...)}
	}
	status := func(msg *dns.Msg, qname string, qtype uint16) ValidationResult {
		return v.ValidateResponse(ctx, msg, dns.Question{Name: qname, Qtype: qtype, Qclass: dns.ClassINET})
	}

	const noError, nameError = dns.RcodeSuccess, dns.RcodeNameError

	BeforeEach(func(specCtx SpecContext) {
		ctx = specCtx
		chain = newSignedChain()

		cut := newRR(insecure + " 300 IN NSEC " + child + " NS RRSIG NSEC")
		dsDenial := &dns.Msg{Ns: inParent(cut)}
		upstream = &mockResolver{ResolveFn: func(ctx context.Context, req *model.Request) (*model.Response, error) {
			if q := req.Req.Question[0]; q.Qtype == dns.TypeDS && q.Name == insecure {
				return &model.Response{Res: dsDenial}, nil
			}

			return chain.resolve(ctx, req)
		}}

		logger, _ := log.NewMockEntry()
		v = NewValidator(ctx, chain.anchors, logger, upstream, 1, 10, 150, 30, 3600)

		junk, _ = badlySigned(inChild(newRR("ns." + child + " 300 IN A 192.0.2.53")))[1].(*dns.RRSIG)
	})

	Describe("the answer section", func() {
		It("is the chain from the query name to the RRset of the query type (RFC 1034 §4.3.2)", func() {
			a := inChild(newRR("www." + child + " 300 IN A 192.0.2.1"))
			cname := inParent(newRR("alias." + parent + " 300 IN CNAME www." + child))
			second := inParent(newRR("second." + parent + " 300 IN CNAME alias." + parent))

			Expect(status(reply(noError, a), "www."+child, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, a), "WWW.Signed.Example.", dns.TypeA)).
				Should(Equal(ValidationResultSecure), "query name in another case")
			Expect(status(reply(noError, slices.Concat(a, cname, second)), "second."+parent, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "CNAME chain in any order")

			Expect(status(reply(noError, inChild(newRR("other."+child+" 300 IN A 192.0.2.1"))), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "RRset of another name")
			Expect(status(reply(noError, inChild(newRR("www."+child+` 300 IN TXT "v=1"`))), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "RRset of another type")
			Expect(status(reply(noError, slices.Concat(cname, inChild(newRR("other."+child+" 300 IN A 192.0.2.1")))),
				"alias."+parent, dns.TypeA)).Should(Equal(ValidationResultBogus), "RRset that the CNAME does not lead to")
			Expect(status(reply(noError, slices.Concat(a, cname)), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "RRset beside the answer")
		})

		It("is the CNAME RRset of the name for a CNAME query, and every RRset of the name for an ANY query", func() {
			a := inChild(newRR("www." + child + " 300 IN A 192.0.2.1"))
			txt := inChild(newRR("www." + child + ` 300 IN TXT "v=1"`))
			cname := inParent(newRR("alias." + parent + " 300 IN CNAME www." + child))

			Expect(status(reply(noError, cname), "alias."+parent, dns.TypeCNAME)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, slices.Concat(cname, a)), "alias."+parent, dns.TypeCNAME)).
				Should(Equal(ValidationResultBogus), "CNAME query with the RRset that the CNAME leads to")

			Expect(status(reply(noError, slices.Concat(a, txt)), "www."+child, dns.TypeANY)).
				Should(Equal(ValidationResultSecure))
			// RFC 8482 §4.2: one synthesized HINFO RRset as the answer
			Expect(status(reply(noError, inChild(newRR("www."+child+` 300 IN HINFO "RFC8482" ""`))), "www."+child, dns.TypeANY)).
				Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, slices.Concat(cname, a)), "alias."+parent, dns.TypeANY)).
				Should(Equal(ValidationResultBogus), "ANY query with the RRset that a CNAME leads to")
		})

		It("is the DS, DNSKEY or NSEC RRset of the name for a query for one", func() {
			nsec := inChild(newRR("www." + child + " 300 IN NSEC " + child + " A RRSIG NSEC"))
			ds := []dns.RR{chain.ds, chain.dsSig}

			Expect(status(reply(noError, ds), child, dns.TypeDS)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, []dns.RR{chain.childKey, chain.childKeySig}), child, dns.TypeDNSKEY)).
				Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, nsec), "www."+child, dns.TypeNSEC)).Should(Equal(ValidationResultSecure))

			Expect(status(reply(noError, nil, ds), child, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "DS RRset in the authority section")
		})

		// A DS question asks the zone above a name whether the name is a zone cut. A name that owns
		// a CNAME RRset has no other data, so it is none, and that RRset is the whole answer. A reply
		// that goes on to the target of the CNAME says what the target has, and must prove it.
		It("is the CNAME RRset of the name for a DS query, if the reply ends with it (RFC 1034 §3.6.2)", func() {
			// alias.example. and out.example. own CNAME RRsets: to a name of the signed zone, which
			// has no DS RRset, and to a name of the unsigned zone. to-zone.example. is an alias of
			// the delegation signed.example., which has one.
			alias := inParent(newRR("alias." + parent + " 300 IN CNAME www." + child))
			out := inParent(newRR("out." + parent + " 300 IN CNAME www." + insecure))
			toZone := inParent(newRR("to-zone." + parent + " 300 IN CNAME " + child))
			ds := []dns.RR{chain.ds, chain.dsSig}
			signedSOA := inChild(soa(child))
			www := inChild(newRR("www." + child + " 300 IN NSEC " + child + " A RRSIG NSEC"))
			ns := newRR(parent + " 300 IN NS ns." + parent)

			Expect(status(reply(noError, alias), "alias."+parent, dns.TypeDS)).
				Should(Equal(ValidationResultSecure), "the CNAME RRset alone")
			Expect(status(reply(noError, out), "out."+parent, dns.TypeDS)).
				Should(Equal(ValidationResultSecure), "the CNAME RRset alone, to a name of the unsigned zone")
			Expect(status(reply(noError, alias, []dns.RR{ns}), "alias."+parent, dns.TypeDS)).
				Should(Equal(ValidationResultSecure), "with an NS RRset that validation leaves out")

			// Without a CNAME RRset the answer is the DS RRset of the name or the denial of it
			Expect(status(reply(noError, ds), child, dns.TypeDS)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, nil, signedSOA, www), "www."+child, dns.TypeDS)).
				Should(Equal(ValidationResultSecure))

			// A reply that goes on is validated to where it ends
			Expect(status(reply(noError, slices.Concat(toZone, ds)), "to-zone."+parent, dns.TypeDS)).
				Should(Equal(ValidationResultSecure), "the DS RRset of the target")
			Expect(status(reply(noError, alias, signedSOA, www), "alias."+parent, dns.TypeDS)).
				Should(Equal(ValidationResultSecure), "the denial of the DS RRset of the target")
			Expect(status(reply(noError, out, []dns.RR{soa(insecure)}), "out."+parent, dns.TypeDS)).
				Should(Equal(ValidationResultInsecure), "no data at a target in the unsigned zone")

			Expect(status(reply(noError, alias, signedSOA), "alias."+parent, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "no data at the target with a signed SOA only")
			Expect(status(reply(noError, alias, inParent(ns)), "alias."+parent, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "an RRset in the authority section and no denial")
			Expect(status(reply(nameError, alias), "alias."+parent, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "name error for the target")
			Expect(status(reply(noError, slices.Concat(inParent(newRR("second."+parent+" 300 IN CNAME alias."+parent)), alias)),
				"second."+parent, dns.TypeDS)).Should(Equal(ValidationResultBogus), "a second CNAME RRset and no more")

			// Only a DS question is answered by the CNAME RRset of its name
			Expect(status(reply(noError, alias), "alias."+parent, dns.TypeA)).Should(Equal(ValidationResultBogus))
		})

		It("has the status of that CNAME RRset, as one of the zone above the name, for a DS query", func() {
			// The zone above a name answers for its DS RRset (RFC 4035 §2.4), and so for the CNAME
			// RRset in its place. in.insecure.example. is a name of the unsigned zone, and
			// insecure.example. its delegation, a name of the signed zone above.
			unsigned := []dns.RR{newRR("alias." + parent + " 300 IN CNAME www." + child)}
			in := []dns.RR{newRR("in." + insecure + " 300 IN CNAME www." + child)}
			atCut := []dns.RR{newRR(insecure + " 300 IN CNAME www." + child)}
			atApex := inChild(newRR(child + " 300 IN CNAME www." + child))

			Expect(status(reply(noError, in), "in."+insecure, dns.TypeDS)).
				Should(Equal(ValidationResultInsecure), "without RRSIG below the insecure delegation")

			Expect(status(reply(noError, atCut), insecure, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "without RRSIG at the insecure delegation")
			Expect(status(reply(noError, unsigned), "alias."+parent, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "without RRSIG in a signed zone")
			Expect(status(reply(noError, badlySigned(inParent(unsigned[0]))), "alias."+parent, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "with an RRSIG that does not verify")

			// The zone at the name signs no RRset of the zone above it
			Expect(status(reply(noError, atApex), child, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "with the RRSIG of the zone at the name")
			Expect(status(reply(noError, atApex), child, dns.TypeCNAME)).
				Should(Equal(ValidationResultSecure), "the same RRset as the answer to a CNAME question")

			// RFC 6672 §3.1: the authenticated DNAME supplies the unsigned CNAME.
			dname := inParent(newRR("d." + parent + " 300 IN DNAME " + child))
			made := []dns.RR{newRR("www.d." + parent + " 300 IN CNAME www." + child)}

			Expect(status(reply(noError, slices.Concat(dname, made)), "www.d."+parent, dns.TypeDS)).
				Should(Equal(ValidationResultSecure), "made from a DNAME")

			// *.w.signed.example. owns a CNAME RRset that answers for x.w.signed.example., which the
			// NSEC record of a.w.signed.example. proves. A reply with NSEC records does not end with
			// its answer, so it says what the target has.
			expanded := expandedTo("x.w."+child, inChild(newRR("*.w."+child+" 300 IN CNAME www."+child)))
			expansion := inChild(newRR("a.w." + child + " 300 IN NSEC www." + child + " A RRSIG NSEC"))
			www := inChild(newRR("www." + child + " 300 IN NSEC " + child + " A RRSIG NSEC"))

			Expect(status(reply(noError, expanded), "x.w."+child, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "of a wildcard, without the proof that it answers for the name")
			Expect(status(reply(noError, expanded, expansion), "x.w."+child, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "of a wildcard, with that proof and nothing of the target")
			Expect(status(reply(noError, expanded, expansion, inChild(soa(child)), www), "x.w."+child, dns.TypeDS)).
				Should(Equal(ValidationResultSecure), "of a wildcard, with that proof and the denial for the target")
		})

		It("holds no data with an RRSIG alone", func() {
			www := newRR("www." + child + " 300 IN NSEC " + child + " A RRSIG NSEC")
			sigOnly := inChild(newRR("www." + child + " 300 IN A 192.0.2.1"))[1:]

			Expect(status(reply(noError, []dns.RR{junk}), junk.Hdr.Name, dns.TypeA)).Should(Equal(ValidationResultBogus))
			Expect(status(reply(noError, sigOnly), "www."+child, dns.TypeA)).Should(Equal(ValidationResultBogus))
			Expect(status(reply(noError, sigOnly, inChild(soa(child)), inChild(www)), "www."+child, dns.TypeTXT)).
				Should(Equal(ValidationResultSecure), "with the proof for an answer without data")
		})

		It("does not go with a name error if it ends with data", func() {
			a := inChild(newRR("www." + child + " 300 IN A 192.0.2.1"))
			cname := inParent(newRR("alias." + parent + " 300 IN CNAME www." + child))

			Expect(status(reply(nameError, a), "www."+child, dns.TypeA)).Should(Equal(ValidationResultBogus))
			Expect(status(reply(nameError, slices.Concat(cname, a)), "alias."+parent, dns.TypeA)).
				Should(Equal(ValidationResultBogus))
		})

		It("bounds an unsigned CNAME by the verified lifetime of its DNAME", func() {
			const name = `one\.two.WwW.d.example.`
			dname := inParent(newRR("D.example. 300 IN DNAME " + child))
			dname[1].Header().Ttl = 45
			alias := newRR(name + ` 300 IN CNAME one\.two.www.` + child)
			answer := slices.Concat([]dns.RR{alias}, dname, inChild(newRR(`one\.two.www.`+child+" 300 IN A 192.0.2.1")))
			verdict := v.Validate(ctx, reply(noError, answer), dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET})
			Expect(verdict.Result).Should(Equal(ValidationResultSecure))
			Expect(verdict.Lifetimes.Bound(answer)[0].Header().Ttl).Should(Equal(uint32(45)))
			Expect(alias.Header().Ttl).Should(Equal(uint32(300)))
		})

		It("requires the DNAME substitution, signer and closest anchor to agree", func() {
			const owner = "old.example."
			const name = "www.old.example."
			d := newRR(owner + " 300 IN DNAME " + child)
			alias := []dns.RR{newRR(name + " 30 IN CNAME www." + child)}
			check := func(ds, cs []dns.RR) ValidationResult {
				return status(reply(noError, slices.Concat(ds, cs)), name, dns.TypeCNAME)
			}
			Expect(check(inParent(d), alias)).Should(Equal(ValidationResultSecure))
			Expect(check(inChild(d), alias)).Should(Equal(ValidationResultBogus), "signer outside the DNAME's zone")
			Expect(check(inParent(d), []dns.RR{newRR(name + " 30 IN CNAME " + child)})).
				Should(Equal(ValidationResultBogus), "missing prefix label")

			_, _, anchor := newSignedZoneKey(name)
			anchors, err := NewTrustAnchorStore([]string{chain.parentKey.String(), anchor})
			Expect(err).Should(Succeed())
			v = NewValidator(ctx, anchors, v.logger, upstream, 1, 10, 150, 30, 3600)
			Expect(check(inParent(d), alias)).Should(Equal(ValidationResultBogus), "closer anchor at the CNAME owner")
		})

		It("may come with the DNAME RRset above a CNAME, which must be authentic beside a Secure answer", func() {
			// island.insecure.example. is a zone below the insecure delegation whose key is a trust
			// anchor too, so its RRsets are Secure. A DNAME RRset of insecure.example. is Insecure.
			const island = "island." + insecure

			key, priv, anchor := newSignedZoneKey(island)
			inIsland := func(rr dns.RR) []dns.RR {
				return []dns.RR{rr, signRRset([]dns.RR{rr}, rr.Header().Rrtype, key, priv, island)}
			}
			keys := &dns.Msg{Answer: inIsland(key)}
			resolve := upstream.ResolveFn
			upstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				if q := req.Req.Question[0]; q.Qtype == dns.TypeDNSKEY && q.Name == island {
					return &model.Response{Res: keys}, nil
				}

				return resolve(ctx, req)
			}

			anchors, err := NewTrustAnchorStore([]string{chain.parentKey.String(), anchor})
			Expect(err).Should(Succeed())

			v = NewValidator(ctx, anchors, v.logger, upstream, 1, 10, 150, 30, 3600)

			answer := slices.Concat(inIsland(newRR("www."+island+" 300 IN CNAME host."+island)),
				inIsland(newRR("host."+island+" 300 IN A 192.0.2.1")))
			dname := []dns.RR{newRR(insecure + " 300 IN DNAME other." + parent)}

			Expect(status(reply(noError, answer), "www."+island, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, slices.Concat(dname, answer)), "www."+island, dns.TypeA)).
				Should(Equal(ValidationResultBogus))
		})
	})

	Describe("an RRset without RRSIG", func() {
		It("has the status of unsigned data at its name, whatever else the reply holds (RFC 4035 §4.3)", func() {
			a := newRR("www." + child + " 300 IN A 192.0.2.1")
			below := newRR("www." + insecure + " 300 IN A 192.0.2.1")

			Expect(status(reply(noError, []dns.RR{a}, inChild(soa(child))), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "signed SOA in the authority section")
			Expect(status(&dns.Msg{Answer: []dns.RR{a}, Extra: []dns.RR{junk}}, "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "RRSIG in the additional section")
			Expect(status(&dns.Msg{Answer: []dns.RR{below}, Extra: []dns.RR{junk}}, "www."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "below the insecure delegation")
			Expect(status(reply(noError, []dns.RR{below}, []dns.RR{soa(insecure)}), "www."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "with other unsigned data below the insecure delegation")
		})

		It("makes a CNAME chain Insecure that crosses an insecure delegation (RFC 4035 §3.2.3)", func() {
			hostA := inChild(newRR("host." + child + " 300 IN A 192.0.2.1"))
			out := inChild(newRR("www." + child + " 300 IN CNAME host." + insecure))
			in := []dns.RR{newRR("www." + insecure + " 300 IN CNAME host." + child)}
			within := []dns.RR{newRR("alias." + insecure + " 300 IN CNAME host." + insecure)}
			unsignedA := []dns.RR{newRR("host." + insecure + " 300 IN A 192.0.2.1")}

			Expect(status(reply(noError, slices.Concat(inChild(newRR("www."+child+" 300 IN CNAME host."+child)), hostA)),
				"www."+child, dns.TypeA)).Should(Equal(ValidationResultSecure), "signed chain")
			Expect(status(reply(noError, slices.Concat(out, unsignedA)), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "into the unsigned zone")
			Expect(status(reply(noError, slices.Concat(in, hostA)), "www."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "out of the unsigned zone")
			Expect(status(reply(noError, slices.Concat(within, unsignedA)), "alias."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "within the unsigned zone")

			// RFC 6672 §3.1: a CNAME made from a DNAME comes with the DNAME RRset
			renamed := []dns.RR{
				newRR("old." + insecure + " 300 IN DNAME " + insecure),
				newRR("host.old." + insecure + " 300 IN CNAME host." + insecure),
			}
			Expect(status(reply(noError, slices.Concat(renamed, unsignedA)), "host.old."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "through a DNAME of the unsigned zone")
		})

		It("costs one DS query for each unsigned zone of a CNAME chain", func() {
			// A chain through eight unsigned zones, each name three labels below its delegation
			var queries int

			upstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				queries++

				if q := req.Req.Question[0]; q.Qtype == dns.TypeDS && strings.HasPrefix(q.Name, "unsigned") {
					cut := newRR(q.Name + " 300 IN NSEC \\000." + q.Name + " NS RRSIG NSEC")

					return &model.Response{Res: &dns.Msg{Ns: inParent(cut)}}, nil
				}

				return chain.resolve(ctx, req)
			}

			name := func(zone int) string { return fmt.Sprintf("c.b.a.unsigned%d.%s", zone, parent) }
			answer := []dns.RR{newRR(name(8) + " 300 IN A 192.0.2.1")}

			for zone := 1; zone < 8; zone++ {
				answer = append(answer, newRR(name(zone)+" 300 IN CNAME "+name(zone+1)))
			}

			Expect(status(reply(noError, answer), name(1), dns.TypeA)).Should(Equal(ValidationResultInsecure))
			Expect(queries).Should(Equal(9), "the DNSKEY RRset of example. and the DS RRset of each zone")
		})

		It("is judged at its own name, not at the query name", func() {
			in := []dns.RR{newRR("www." + insecure + " 300 IN CNAME host." + child)}
			forged := []dns.RR{newRR("host." + child + " 300 IN A 192.0.2.66")}

			Expect(status(reply(noError, slices.Concat(in, forged)), "www."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultBogus))
		})
	})

	Describe("the authority section", func() {
		It("is validated beside an answer with data (RFC 4035 §3.2.3)", func() {
			a := inChild(newRR("www." + child + " 300 IN A 192.0.2.1"))
			ns := inChild(newRR(child + " 300 IN NS ns." + child))
			glue := []dns.RR{newRR("ns." + child + " 300 IN A 192.0.2.53")}

			Expect(status(reply(noError, a, ns), "www."+child, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(status(&dns.Msg{Answer: a, Ns: ns, Extra: glue}, "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "with an address of the name server in the additional section")

			Expect(status(reply(noError, a, badlySigned(ns)), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NS RRset with an RRSIG that does not verify")
			Expect(status(reply(noError, a, []dns.RR{soa(child)}), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "SOA RRset without RRSIG")
		})

		It("does not make a Secure answer Insecure (RFC 4035 §3.2.3)", func() {
			// The SOA RRset of the unsigned zone, as that zone holds it and with an RRSIG that names
			// the zone as its signer: both are Insecure
			a := inChild(newRR("www." + child + " 300 IN A 192.0.2.1"))
			unsigned := []dns.RR{soa(insecure)}
			madeUp := *junk
			madeUp.Hdr.Name, madeUp.TypeCovered, madeUp.SignerName = insecure, dns.TypeSOA, insecure
			below := []dns.RR{newRR("www." + insecure + " 300 IN A 192.0.2.1")}

			Expect(status(reply(noError, a, unsigned), "www."+child, dns.TypeA)).Should(Equal(ValidationResultBogus))
			Expect(status(reply(noError, a, unsigned, []dns.RR{&madeUp}), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "with an RRSIG of the unsigned zone")
			Expect(status(reply(nameError, nil, inChild(soa(child)),
				inChild(newRR(child+" 300 IN NSEC www."+child+" NS SOA RRSIG NSEC DNSKEY")), unsigned), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "beside a proven name error")

			Expect(status(reply(noError, below, unsigned), "www."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "beside an Insecure answer")
			Expect(status(reply(noError, below, inChild(soa(child))), "www."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "a Secure RRset does not make an Insecure answer better")
			Expect(status(reply(noError, below, badlySigned(inChild(soa(child)))), "www."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "a Bogus RRset makes every reply Bogus")
		})

		It("is validated without its NS RRsets that have no RRSIG, unless one is all that a reply without answer holds", func() {
			// A forwarder may add the NS RRset of a zone, which it holds without RRSIG, to a reply.
			// Unbound takes such an RRset out of a reply (remove_spurious_authority).
			a := inChild(newRR("www." + child + " 300 IN A 192.0.2.1"))
			ns := newRR(child + " 300 IN NS ns." + child)
			denial := slices.Concat(inChild(soa(child)),
				inChild(newRR(child+" 300 IN NSEC www."+child+" NS SOA RRSIG NSEC DNSKEY")))

			positive := reply(noError, a, []dns.RR{ns})
			Expect(status(positive, "www."+child, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(ValidatedAuthority(positive)).Should(BeEmpty())
			Expect(positive.Ns).Should(HaveLen(1), "validation does not change the reply")

			negative := reply(nameError, nil, denial, []dns.RR{ns})
			Expect(status(negative, "nx."+child, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(ValidatedAuthority(negative)).Should(Equal(denial))

			signed := reply(noError, a, inChild(ns))
			Expect(status(signed, "www."+child, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(ValidatedAuthority(signed)).Should(HaveLen(2), "an NS RRset with its RRSIG is validated")

			only := reply(noError, nil, []dns.RR{ns})
			Expect(status(only, "www."+child, dns.TypeA)).Should(Equal(ValidationResultBogus))
			Expect(ValidatedAuthority(only)).Should(HaveLen(1))

			below := reply(noError, nil, []dns.RR{newRR(insecure + " 300 IN NS ns." + insecure)})
			Expect(status(below, "www."+insecure, dns.TypeA)).Should(Equal(ValidationResultInsecure))
		})
	})

	Describe("an answer that ends without data", func() {
		var apex, www []dns.RR

		BeforeEach(func() {
			// The NSEC records of signed.example., whose names are the apex and www
			apex = inChild(newRR(child + " 300 IN NSEC www." + child + " NS SOA RRSIG NSEC DNSKEY"))
			www = inChild(newRR("www." + child + " 300 IN NSEC " + child + " A RRSIG NSEC"))
		})

		It("needs NSEC or NSEC3 records that prove it (RFC 4035 §5.4)", func() {
			signedSOA := inChild(soa(child))
			closest := inChild(nsec3Range(child, child, 0, 1, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY))
			nextCloser := inChild(nsec3Range(child, "nx."+child, -1, 1))
			wildcard := inChild(nsec3Range(child, "*."+child, -1, 1))

			Expect(status(reply(nameError, nil, signedSOA, apex), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "name error with NSEC")
			Expect(status(reply(nameError, nil, signedSOA, closest, nextCloser, wildcard), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "name error with NSEC3")
			Expect(status(reply(noError, nil, signedSOA, www), "www."+child, dns.TypeTXT)).
				Should(Equal(ValidationResultSecure), "no data with NSEC")
			Expect(status(reply(noError, nil, signedSOA,
				inChild(nsec3Range(child, "www."+child, 0, 1, dns.TypeA, dns.TypeRRSIG))), "www."+child, dns.TypeTXT)).
				Should(Equal(ValidationResultSecure), "no data with NSEC3")

			Expect(status(reply(nameError, nil, signedSOA), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name error with a signed SOA only")
			Expect(status(reply(noError, nil, signedSOA), "www."+child, dns.TypeTXT)).
				Should(Equal(ValidationResultBogus), "no data with a signed SOA only")
			Expect(status(reply(noError, nil), "www."+child, dns.TypeTXT)).
				Should(Equal(ValidationResultBogus), "no data with nothing")
			Expect(status(&dns.Msg{Rcode: nameError, Ns: []dns.RR{soa(child)}, Extra: []dns.RR{junk}},
				"nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name error with an unsigned SOA and an RRSIG in the additional section")

			Expect(status(&dns.Msg{Rcode: nameError, Ns: []dns.RR{soa(insecure)}, Extra: []dns.RR{junk}},
				"nx."+insecure, dns.TypeA)).Should(Equal(ValidationResultInsecure), "name error below the insecure delegation")
			Expect(status(reply(noError, nil, []dns.RR{soa(insecure)}), "www."+insecure, dns.TypeTXT)).
				Should(Equal(ValidationResultInsecure), "no data below the insecure delegation")

			// A proof whose chain of trust cannot be walked is none below a trust anchor, like a
			// reply without the records of a proof
			upstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				if q := req.Req.Question[0]; q.Qtype == dns.TypeDNSKEY && q.Name == child {
					return nil, errors.New("i/o timeout")
				}

				return chain.resolve(ctx, req)
			}
			v = NewValidator(ctx, chain.anchors, v.logger, upstream, 1, 10, 150, 30, 3600)

			Expect(status(reply(nameError, nil, signedSOA, apex), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus))
			Expect(status(reply(nameError, nil, signedSOA), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus))
		})

		It("is not proven by NSEC records that are not Secure", func() {
			// The NSEC record of an unsigned zone, which covers every other name
			unsigned := newRR("a." + insecure + " 300 IN NSEC a." + insecure + " A NSEC")

			Expect(status(reply(nameError, nil, inChild(soa(child)), []dns.RR{unsigned}), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus))
			Expect(status(reply(nameError, nil, []dns.RR{soa(insecure), unsigned}), "nx."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "below the insecure delegation")
		})

		It("is not proven by the record of a name that owns a CNAME (RFC 6840 §4.3)", func() {
			// A name that owns a CNAME RRset has no other data: the answer for another type at that
			// name is the CNAME RRset, so its NSEC or NSEC3 record denies no type. alias.signed.example.
			// owns a CNAME RRset, and so does the wildcard *.w.signed.example.
			signedSOA := inChild(soa(child))
			alias := inChild(newRR("alias." + child + " 300 IN NSEC www." + child + " CNAME RRSIG NSEC"))
			alias3 := inChild(nsec3Range(child, "alias."+child, 0, 1, dns.TypeCNAME, dns.TypeRRSIG))
			cover := inChild(newRR("a.w." + child + " 300 IN NSEC www." + child + " A RRSIG NSEC"))
			wildcard := inChild(newRR("*.w." + child + " 300 IN NSEC a.w." + child + " CNAME RRSIG NSEC"))
			wildcard3 := slices.Concat(inChild(nsec3Range(child, "w."+child, 0, 1)),
				inChild(nsec3Range(child, "x.w."+child, -1, 1)),
				inChild(nsec3Range(child, "*.w."+child, 0, 1, dns.TypeCNAME, dns.TypeRRSIG)))

			Expect(status(reply(noError, nil, signedSOA, www), "www."+child, dns.TypeTXT)).
				Should(Equal(ValidationResultSecure), "record of a name without CNAME RRset")

			Expect(status(reply(noError, nil, signedSOA, alias), "alias."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC record of the name")
			Expect(status(reply(noError, nil, signedSOA, alias3), "alias."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC3 record of the name")
			Expect(status(reply(noError, nil, signedSOA, cover, wildcard), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC record of the wildcard that answers for the name")
			Expect(status(reply(noError, nil, signedSOA, wildcard3), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC3 record of the wildcard that answers for the name")

			// A name that owns a CNAME RRset is no delegation, and a query for its DS RRset gets the
			// CNAME RRset like any other
			Expect(status(reply(noError, nil, signedSOA, alias), "alias."+child, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "DS RRset, NSEC")
			Expect(status(reply(noError, nil, signedSOA, alias3), "alias."+child, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "DS RRset, NSEC3")

			// For a CNAME question the type that the record must lack is CNAME
			Expect(status(reply(noError, nil, signedSOA, www), "www."+child, dns.TypeCNAME)).
				Should(Equal(ValidationResultSecure), "CNAME question at a name without CNAME RRset")
			Expect(status(reply(noError, nil, signedSOA, alias), "alias."+child, dns.TypeCNAME)).
				Should(Equal(ValidationResultBogus), "CNAME question at the name that owns one")
		})

		It("needs the proof for the name at which a CNAME chain ends", func() {
			toNowhere := inParent(newRR("gone." + parent + " 300 IN CNAME nx." + child))
			toWWW := inParent(newRR("alias." + parent + " 300 IN CNAME www." + child))
			toInsecure := inParent(newRR("out." + parent + " 300 IN CNAME www." + insecure))
			signedSOA := inChild(soa(child))

			Expect(status(reply(nameError, toNowhere, signedSOA, apex), "gone."+parent, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "name error for the target, in another zone")
			Expect(status(reply(noError, toWWW, signedSOA, www), "alias."+parent, dns.TypeTXT)).
				Should(Equal(ValidationResultSecure), "no data at the target, in another zone")
			// RFC 2308 §2.2.1, RFC 6604 §3: a reply may say that the target of a CNAME does not exist
			// without the rcode of a name error
			Expect(status(reply(noError, toNowhere, signedSOA, apex), "gone."+parent, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "proof of a name error for the target without the rcode")

			Expect(status(reply(nameError, toNowhere, signedSOA), "gone."+parent, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name error with a signed SOA only")
			Expect(status(reply(noError, toWWW, signedSOA), "alias."+parent, dns.TypeTXT)).
				Should(Equal(ValidationResultBogus), "no data with a signed SOA only")
			Expect(status(reply(noError, toWWW), "alias."+parent, dns.TypeTXT)).
				Should(Equal(ValidationResultBogus), "no data with nothing")
			Expect(status(reply(noError, nil, signedSOA, apex), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "proof of a name error for the query name without the rcode")
			Expect(status(reply(noError, toWWW, signedSOA, www), "alias."+parent, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC record that has the type")

			Expect(status(reply(noError, toInsecure, []dns.RR{soa(insecure)}), "out."+parent, dns.TypeTXT)).
				Should(Equal(ValidationResultInsecure), "no data at a target below the insecure delegation")
			Expect(status(reply(nameError, toInsecure), "out."+parent, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "name error for a target below the insecure delegation")
		})
	})

	// A denial of existence is given by the zone that holds the name (RFC 4035 §5.4): for the end
	// of an answer, the closest zone above it that signed NSEC or NSEC3 records of the reply. A
	// record at a zone cut says what its side of the cut holds (RFC 6840 §4.1), so the records of a
	// zone deny nothing at or below a zone cut of that zone, and a reply may carry whatever records
	// a zone above the name has. Where the reply proves nothing, the answer has the status of
	// unsigned data at the name.
	//
	// The NSEC records are those of zones with these names: example. has the delegations
	// insecure.example., signed.example. and twin.example., and signed.example. has the name www.
	Describe("the zone that gives a denial", func() {
		type zone struct {
			sign   func(rrset ...dns.RR) []dns.RR // An RRset followed by the RRSIG that the zone makes for it
			keys   []dns.RR                       // The DNSKEY RRset of the zone with its RRSIG
			ds     dns.RR                         // The DS record for its key
			anchor string                         // Its key as a trust anchor
		}

		var (
			replies map[string]*dns.Msg // Replies to queries of the validator, by name and type
			asked   []string            // Its queries

			parentSOA, parentApex, insecureCut, signedCut []dns.RR
			childSOA, apex, www                           []dns.RR
			parentApex3, insecureCut3, signedCut3, noWild []dns.RR
		)

		// newZone returns a zone with a new key
		newZone := func(name string) zone {
			key, priv, anchor := newSignedZoneKey(name)
			sign := func(rrset ...dns.RR) []dns.RR {
				return append(slices.Clone(rrset), signRRset(rrset, rrset[0].Header().Rrtype, key, priv, name))
			}

			return zone{sign: sign, keys: sign(key), ds: key.ToDS(dns.SHA256), anchor: anchor}
		}
		// withAnchor makes v a validator that also has the key of z as a trust anchor
		withAnchor := func(z zone) {
			anchors, err := NewTrustAnchorStore([]string{chain.parentKey.String(), z.anchor})
			Expect(err).Should(Succeed())

			v = NewValidator(ctx, anchors, v.logger, upstream, 1, 10, 150, 30, 3600)
		}
		// optOut returns the NSEC3 record of zone that covers the hash of name, with the Opt-Out flag
		optOut := func(zone, name string) *dns.NSEC3 {
			rr := nsec3Range(zone, name, -1, 1)
			rr.Flags = 1

			return rr
		}

		BeforeEach(func() {
			replies, asked = map[string]*dns.Msg{}, nil
			lookup := upstream.ResolveFn
			upstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				id := req.Req.Question[0].Name + " " + dns.TypeToString[req.Req.Question[0].Qtype]
				asked = append(asked, id)

				if msg, found := replies[id]; found {
					return &model.Response{Res: msg}, nil
				}

				return lookup(ctx, req)
			}

			parentSOA, childSOA = inParent(soa(parent)), inChild(soa(child))
			parentApex = inParent(newRR(parent + " 300 IN NSEC " + insecure + " NS SOA RRSIG NSEC DNSKEY"))
			insecureCut = inParent(newRR(insecure + " 300 IN NSEC " + child + " NS RRSIG NSEC"))
			signedCut = inParent(newRR(child + " 300 IN NSEC twin." + parent + " NS DS RRSIG NSEC"))
			apex = inChild(newRR(child + " 300 IN NSEC www." + child + " NS SOA RRSIG NSEC DNSKEY"))
			www = inChild(newRR("www." + child + " 300 IN NSEC " + child + " A RRSIG NSEC"))

			// The same names with NSEC3 records of example., and the record that covers its wildcard
			parentApex3 = inParent(nsec3Range(parent, parent, 0, 1, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY))
			insecureCut3 = inParent(nsec3Range(parent, insecure, 0, 1, dns.TypeNS))
			signedCut3 = inParent(nsec3Range(parent, child, 0, 1, dns.TypeNS, dns.TypeDS, dns.TypeRRSIG))
			noWild = inParent(nsec3Range(parent, "*."+parent, -1, 1))
		})

		It("is the zone that holds the name, not a zone above it", func() {
			// d.example. has a DNAME RRset
			dname := inParent(newRR("d." + parent + " 300 IN NSEC " + insecure + " DNAME RRSIG NSEC"))

			Expect(status(reply(nameError, nil, childSOA, apex), "nx."+child, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(nameError, nil, parentApex3, signedCut3, noWild, childSOA, apex), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "NSEC records of the zone after NSEC3 records of the zone above")
			Expect(status(reply(nameError, nil, parentSOA, signedCut, childSOA,
				inChild(nsec3Range(child, child, 0, 1, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY)),
				inChild(nsec3Range(child, "nx."+child, -1, 1)), inChild(nsec3Range(child, "*."+child, -1, 1))),
				"nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "NSEC3 records of the zone after NSEC records of the zone above")

			Expect(status(reply(nameError, nil, parentSOA, signedCut), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name error below a delegation by its NSEC record")
			Expect(status(reply(nameError, nil, parentApex3, signedCut3, noWild), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name error below a delegation by its NSEC3 record")
			Expect(status(reply(noError, nil, parentSOA, signedCut), child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "no data at a delegation by its NSEC record")
			Expect(status(reply(noError, nil, parentSOA, signedCut3), child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "no data at a delegation by its NSEC3 record")
			Expect(status(reply(nameError, nil, parentSOA, dname), "nx.d."+parent, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name error below a DNAME by its NSEC record")
			Expect(status(reply(noError, nil, parentSOA, dname), "d."+parent, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "no data at the name that has the DNAME RRset")
		})

		It("leaves a name of an insecure zone Insecure, whatever records of the zone above come with it", func() {
			Expect(status(reply(nameError, nil, parentSOA, parentApex, insecureCut), "nx."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "name error with the NSEC record of the delegation")
			Expect(status(reply(noError, nil, parentSOA, insecureCut), insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "no data at the delegation with its NSEC record")
			Expect(status(reply(noError, nil, parentSOA, parentApex, insecureCut), "www."+insecure, dns.TypeTXT)).
				Should(Equal(ValidationResultInsecure), "no data below the delegation with its NSEC record")
			Expect(status(reply(nameError, nil, parentSOA, parentApex3, insecureCut3, noWild), "nx."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "name error with the NSEC3 record of the delegation")
			Expect(status(reply(noError, nil, parentSOA, insecureCut3), insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "no data at the delegation with its NSEC3 record")
			Expect(status(reply(nameError, nil, parentSOA, parentApex3, inParent(optOut(parent, insecure)), noWild),
				"nx."+insecure, dns.TypeA)).Should(Equal(ValidationResultInsecure), "name error with an Opt-Out proof")

			// The zone may sign its records with a key that nothing leads to: they prove nothing
			own := newZone(insecure).sign(newRR("a." + insecure + " 300 IN NSEC z." + insecure + " A RRSIG NSEC"))
			Expect(status(reply(nameError, nil, own), "nx."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "name error with an NSEC record that the zone signs")
		})

		It("takes no record of a zone that is not above the name", func() {
			twin := newZone("twin." + parent)
			replies["twin.example. DS"] = &dns.Msg{Answer: inParent(twin.ds)}
			replies["twin.example. DNSKEY"] = &dns.Msg{Answer: twin.keys}

			// The NSEC records of twin.example.: the last one covers the names of the zone after www,
			// and the one of the apex the wildcard *.twin.example. In the order of names, names of
			// other zones are after www.twin.example. too.
			last := twin.sign(newRR("www.twin." + parent + " 300 IN NSEC twin." + parent + " A RRSIG NSEC"))
			named, _ := dns.Copy(last[1]).(*dns.RRSIG)
			named.SignerName = parent
			first := twin.sign(newRR("twin." + parent + " 300 IN NSEC www.twin." + parent + " NS SOA RRSIG NSEC DNSKEY"))

			Expect(status(reply(nameError, nil, last, first), "zz.twin."+parent, dns.TypeA)).
				Should(Equal(ValidationResultSecure))
			Expect(status(reply(nameError, nil, last, first), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name of a sibling zone")
			Expect(status(reply(nameError, nil, last, first, []dns.RR{named}), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "with an RRSIG that names the zone above and does not verify")
			Expect(status(reply(nameError, nil, last, first), "nx."+parent, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name of the zone above")
			Expect(status(reply(nameError, nil, last, first), parent, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name above the zone")

			// An NSEC3 record is of the zone that its owner name is in (RFC 5155 §3): example. signs
			// these, with owner names under signed.example.
			Expect(status(reply(nameError, nil,
				inParent(nsec3Range(child, child, 0, 1, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY)),
				inParent(nsec3Range(child, "nx."+child, -1, 1)), inParent(nsec3Range(child, "*."+child, -1, 1))),
				"nx."+child, dns.TypeA)).Should(Equal(ValidationResultBogus), "NSEC3 records named after another zone")
		})

		It("takes no record of a zone above a trust anchor that covers the name (RFC 6840 §5.10)", func() {
			// island.example. is no delegation of example., and its key is a trust anchor
			island := newZone("island." + parent)
			replies["island.example. DNSKEY"] = &dns.Msg{Answer: island.keys}

			withAnchor(island)

			Expect(status(reply(noError, island.sign(newRR("www.island."+parent+" 300 IN A 192.0.2.1"))),
				"www.island."+parent, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(nameError, nil, island.sign(soa("island."+parent)),
				island.sign(newRR("island."+parent+" 300 IN NSEC www.island."+parent+" NS SOA RRSIG NSEC DNSKEY"))),
				"nx.island."+parent, dns.TypeA)).Should(Equal(ValidationResultSecure), "name error by the zone of the anchor")

			Expect(status(reply(nameError, nil, parentSOA, insecureCut), "nx.island."+parent, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name error by an NSEC record of the zone above")
			Expect(status(reply(nameError, nil, parentSOA, parentApex3, inParent(optOut(parent, "island."+parent)), noWild),
				"nx.island."+parent, dns.TypeA)).Should(Equal(ValidationResultBogus), "Opt-Out proof of the zone above")

			// *.example. as the answer for a name below the anchor, with an Opt-Out record of example.
			// that covers every name but its apex
			alone := nsec3Range(parent, parent, 0, 0, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY)
			alone.Flags = 1
			Expect(status(reply(noError,
				expandedTo("www.island."+parent, inParent(newRR("*."+parent+" 300 IN A 192.0.2.66"))), inParent(alone)),
				"www.island."+parent, dns.TypeA)).Should(Equal(ValidationResultBogus), "wildcard of the zone above")
		})

		It("needs no query but those for the keys of the zone, also below a name that owns a CNAME", func() {
			// alias.signed.example. owns a CNAME RRset, which is what the reply to a DS query for it
			// would hold.
			alias := inChild(newRR("alias." + child + " 300 IN NSEC www." + child + " CNAME RRSIG NSEC"))
			alias3 := slices.Concat(inChild(nsec3Range(child, "alias."+child, 0, 1, dns.TypeCNAME, dns.TypeRRSIG)),
				inChild(nsec3Range(child, "_dmarc.alias."+child, -1, 1)), inChild(nsec3Range(child, "*.alias."+child, -1, 1)))
			www3 := inChild(nsec3Range(child, "www."+child, 0, 1, dns.TypeA, dns.TypeRRSIG))
			replies["alias.signed.example. DS"] = &dns.Msg{
				Answer: inChild(newRR("alias." + child + " 300 IN CNAME www." + insecure)), Ns: []dns.RR{soa(insecure)},
			}

			// queries returns what a validator that knows no zone asks upstream for a Secure reply,
			// after checking that it asks nothing when it validates the reply again
			queries := func(msg *dns.Msg, qname string, qtype uint16) []string {
				v = NewValidator(ctx, chain.anchors, v.logger, upstream, 1, 10, 150, 30, 3600)
				asked = nil

				Expect(status(msg, qname, qtype)).Should(Equal(ValidationResultSecure), "%s %d", qname, qtype)

				first := asked
				asked = nil

				Expect(status(msg, qname, qtype)).Should(Equal(ValidationResultSecure), "%s %d again", qname, qtype)
				Expect(asked).Should(BeEmpty(), "%s %d again", qname, qtype)

				return first
			}

			// The queries for the keys of signed.example., which a signed answer of the zone costs
			keys := queries(reply(noError, inChild(newRR("www."+child+" 300 IN A 192.0.2.1"))), "www."+child, dns.TypeA)
			Expect(keys).Should(Equal([]string{"example. DNSKEY", "signed.example. DS", "signed.example. DNSKEY"}))

			Expect(queries(reply(nameError, nil, childSOA, apex), "nx."+child, dns.TypeA)).Should(Equal(keys))
			Expect(queries(reply(nameError, nil, childSOA, apex), "c.b.a.nx."+child, dns.TypeA)).Should(Equal(keys))
			Expect(queries(reply(noError, nil, childSOA, www), "www."+child, dns.TypeTXT)).Should(Equal(keys))
			Expect(queries(reply(noError, nil, childSOA, www3), "www."+child, dns.TypeTXT)).Should(Equal(keys))
			Expect(queries(reply(nameError, nil, childSOA, alias), "_dmarc.alias."+child, dns.TypeTXT)).Should(Equal(keys))
			Expect(queries(reply(nameError, nil, childSOA, alias3), "_dmarc.alias."+child, dns.TypeTXT)).Should(Equal(keys))
		})

		It("denies a DS RRset with the records of the zone above its name (RFC 4035 §2.4)", func() {
			// *.signed.example. has an A RRset and answers for x.signed.example.
			closest := inChild(nsec3Range(child, child, 0, 1, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY))
			nextCloser := inChild(nsec3Range(child, "x."+child, -1, 1))
			wildcard := inChild(nsec3Range(child, "*."+child, 0, 1, dns.TypeA, dns.TypeRRSIG))
			www3 := inChild(nsec3Range(child, "www."+child, 0, 1, dns.TypeA, dns.TypeRRSIG))

			Expect(status(reply(noError, nil, parentSOA, insecureCut), insecure, dns.TypeDS)).
				Should(Equal(ValidationResultSecure), "delegation without DS RRset, NSEC")
			Expect(status(reply(noError, nil, parentSOA, insecureCut3), insecure, dns.TypeDS)).
				Should(Equal(ValidationResultSecure), "delegation without DS RRset, NSEC3")
			Expect(status(reply(noError, nil, parentSOA, parentApex3, inParent(optOut(parent, insecure))), insecure, dns.TypeDS)).
				Should(Equal(ValidationResultInsecure), "delegation that Opt-Out leaves out of the NSEC3 chain")
			Expect(status(reply(noError, nil, childSOA, www), "www."+child, dns.TypeDS)).
				Should(Equal(ValidationResultSecure), "name that is no zone cut, NSEC")
			Expect(status(reply(noError, nil, childSOA, www3), "www."+child, dns.TypeDS)).
				Should(Equal(ValidationResultSecure), "name that is no zone cut, NSEC3")
			Expect(status(reply(noError, nil, childSOA, closest, nextCloser, wildcard), "x."+child, dns.TypeDS)).
				Should(Equal(ValidationResultSecure), "name that a wildcard answers for, NSEC3")
			Expect(status(reply(noError, nil, childSOA, closest, inChild(optOut(child, "x."+child)), wildcard),
				"x."+child, dns.TypeDS)).Should(Equal(ValidationResultInsecure), "the same below an Opt-Out record")

			Expect(status(reply(noError, nil, parentSOA, signedCut), child, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "NSEC record that has the DS type")
			Expect(status(reply(noError, nil, childSOA, closest, wildcard), "x."+child, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "wildcard without the closest encloser proof")
			Expect(status(reply(noError, nil, childSOA, apex), child, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "NSEC record of the apex of the zone below")
			Expect(status(reply(noError, nil, childSOA, closest), child, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "NSEC3 record of the apex of the zone below")
		})

		It("reads the denial of a DS RRset in the chain of trust walk from the records of the zone above", func() {
			// Here twin.example. is a delegation without DS RRset
			unsigned := reply(noError, []dns.RR{newRR("www.twin." + parent + " 300 IN A 192.0.2.1")})

			replies["twin.example. DS"] = &dns.Msg{Ns: inParent(nsec3Range(parent, "twin."+parent, 0, 1, dns.TypeNS))}
			Expect(status(unsigned, "www.twin."+parent, dns.TypeA)).Should(Equal(ValidationResultInsecure))

			// An NSEC3 record is of the zone that its owner name is in (RFC 5155 §3): example. signs
			// this one, with an owner name under sub.example.
			replies["twin.example. DS"] = &dns.Msg{Ns: inParent(nsec3Range("sub."+parent, "twin."+parent, 0, 1, dns.TypeNS))}
			v = NewValidator(ctx, chain.anchors, v.logger, upstream, 1, 10, 150, 30, 3600)

			Expect(status(unsigned, "www.twin."+parent, dns.TypeA)).Should(Equal(ValidationResultBogus))
		})

		It("takes no NSEC3 record of a wildcard for that of a delegation in the chain of trust walk", func() {
			// RFC 5155 §8.6, §8.9: a delegation is insecure by its own NSEC3 record, or by an Opt-Out
			// record that covers its next closer name. Here example. has *.example. with an NS RRset,
			// and the reply to the DS query for signed.example. holds the NSEC3 records of the apex
			// and of the wildcard, without the one of the delegation.
			wildcard := inParent(nsec3Range(parent, "*."+parent, 0, 1, dns.TypeNS))
			unsigned := reply(noError, []dns.RR{newRR("www." + child + " 300 IN A 192.0.2.66")})

			replies["signed.example. DS"] = &dns.Msg{Ns: slices.Concat(parentApex3, wildcard)}
			Expect(status(unsigned, "www."+child, dns.TypeA)).Should(Equal(ValidationResultBogus))

			// The Opt-Out record that covers the next closer name does make the delegation insecure
			replies["twin.example. DS"] = &dns.Msg{
				Ns: slices.Concat(parentApex3, wildcard, inParent(optOut(parent, "twin."+parent))),
			}
			Expect(status(reply(noError, []dns.RR{newRR("www.twin." + parent + " 300 IN A 192.0.2.1")}),
				"www.twin."+parent, dns.TypeA)).Should(Equal(ValidationResultInsecure))
		})

		It("takes no NSEC record in the chain of trust walk that an RRSIG made for a wildcard verified", func() {
			// What example. signs if *.example. has an NS RRset: the NSEC record of the wildcard. Its
			// RRSIG verifies it under the name of the delegation signed.example. too, where it says
			// nothing (RFC 4035 §5.4).
			wildcard := expandedTo(child, inParent(newRR("*."+parent+" 300 IN NSEC "+insecure+" NS RRSIG NSEC")))
			unsigned := reply(noError, []dns.RR{newRR("www." + child + " 300 IN A 192.0.2.66")})

			replies["signed.example. DS"] = &dns.Msg{Ns: wildcard}
			Expect(status(unsigned, "www."+child, dns.TypeA)).Should(Equal(ValidationResultBogus))
		})

		It("has a DS RRset in the zone above its name, also for the trust anchor that covers it", func() {
			// insecure.example. signs its records, and example. has no DS RRset for it.
			// anchored.insecure.example. is a delegation of it whose key is a trust anchor.
			unchained, anchored := newZone(insecure), newZone("anchored."+insecure)
			replies["anchored.insecure.example. DNSKEY"] = &dns.Msg{Answer: anchored.keys}

			withAnchor(anchored)

			Expect(status(reply(noError, anchored.sign(newRR("www.anchored."+insecure+" 300 IN A 192.0.2.1"))),
				"www.anchored."+insecure, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, unchained.sign(anchored.ds)), "anchored."+insecure, dns.TypeDS)).
				Should(Equal(ValidationResultInsecure), "the DS RRset is a record of the insecure zone")
			Expect(status(reply(noError, unchained.sign(newRR("anchored."+insecure+" 300 IN A 192.0.2.1"))),
				"anchored."+insecure, dns.TypeA)).Should(Equal(ValidationResultBogus), "other records are those of the anchor's zone")
		})

		It("has the NSEC record of a delegation in the zone above its name", func() {
			below := []dns.RR{newRR("www." + insecure + " 300 IN A 192.0.2.1")}

			Expect(status(reply(noError, below, insecureCut[:1]), "www."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "without RRSIG it is unsigned data of the signed zone")
			Expect(status(reply(noError, below, []dns.RR{newRR(insecure + " 300 IN NSEC www." + insecure + " NS SOA NSEC")}),
				"www."+insecure, dns.TypeA)).Should(Equal(ValidationResultInsecure), "NSEC record of the apex of the unsigned zone")
			Expect(status(reply(noError, below, []dns.RR{newRR("a." + insecure + " 300 IN NSEC www." + insecure + " A NSEC")}),
				"www."+insecure, dns.TypeA)).Should(Equal(ValidationResultInsecure), "NSEC record below the delegation")
		})

		It("takes no RRSIG for the NSEC record of a delegation from the zone at its name", func() {
			// RFC 4035 §5.3.1: the signer of an RRset is the zone that holds it, which for the NSEC
			// record of a delegation is the zone above (RFC 6840 §4.1). Here signed.example. signs a
			// record at its apex with the type bitmap of a delegation, beside a signed answer.
			a := inChild(newRR("www." + child + " 300 IN A 192.0.2.1"))
			delegation := inChild(newRR(child + " 300 IN NSEC www." + child + " NS RRSIG NSEC"))

			Expect(status(reply(noError, a, apex), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "NSEC record of the apex, signed by its zone")
			Expect(status(reply(noError, a, signedCut), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "NSEC record of the delegation, signed by the zone above")
			Expect(status(reply(noError, a, delegation), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "the bitmap of a delegation, signed by the zone at its name")

			// The same with the key of signed.example. as the only trust anchor: no trust anchor is
			// above the zone, and the zone still does not hold that record
			anchors, err := NewTrustAnchorStore([]string{chain.childKey.String()})
			Expect(err).Should(Succeed())

			v = NewValidator(ctx, anchors, v.logger, upstream, 1, 10, 150, 30, 3600)

			Expect(status(reply(noError, a, apex), "www."+child, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, a, delegation), "www."+child, dns.TypeA)).Should(Equal(ValidationResultBogus))
		})

		It("has an NSEC3 record in the zone that its owner name names (RFC 5155 §3)", func() {
			below := []dns.RR{newRR("www." + insecure + " 300 IN A 192.0.2.1")}

			Expect(status(reply(noError, below, insecureCut3[:1]), "www."+insecure, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "without RRSIG it is unsigned data of the signed zone")
			Expect(status(reply(noError, below, []dns.RR{nsec3Range(insecure, "a."+insecure, 0, 1, dns.TypeA)}),
				"www."+insecure, dns.TypeA)).Should(Equal(ValidationResultInsecure), "NSEC3 record of the unsigned zone")
			Expect(asked).Should(Equal([]string{"example. DNSKEY", "insecure.example. DS"}),
				"a hashed owner name is no name to ask about")
		})

		It("gives a CNAME into an unsigned zone the status of that zone", func() {
			// *.signed.example. is a CNAME to www.insecure.example., which has no HTTPS RRset. The
			// last NSEC record of signed.example. proves the expansion for zz.signed.example., and in
			// the order of names it also covers the target: a name before the apex of the zone.
			cname := expandedTo("zz."+child, inChild(newRR("*."+child+" 300 IN CNAME www."+insecure)))

			Expect(status(reply(noError, cname, []dns.RR{soa(insecure)}, www), "zz."+child, dns.TypeHTTPS)).
				Should(Equal(ValidationResultInsecure))
			Expect(status(reply(noError, cname, www, []dns.RR{soa(insecure)}), "zz."+child, dns.TypeHTTPS)).
				Should(Equal(ValidationResultInsecure), "records in another order")
			Expect(status(reply(nameError, cname, www, []dns.RR{soa(insecure)}), "zz."+child, dns.TypeHTTPS)).
				Should(Equal(ValidationResultInsecure), "name error for the target")
		})
	})

	// A wildcard answers for a name that does not exist and has no closer match (RFC 4592 §3.3.1).
	// What it gives a name is authentic with the proof that the name does not exist and that the
	// wildcard is the one at its closest encloser: an RRset that an RRSIG made for the wildcard
	// verifies (RFC 4035 §5.3.4, RFC 5155 §8.8), and "no data" by the record of the wildcard
	// (RFC 4035 §3.1.3.4, RFC 5155 §8.7). A name error needs the same proof and the denial of that
	// wildcard (RFC 4035 §5.4). The zone gives the proof with records that it signed for their own
	// owner names.
	//
	// signed.example. has the names *.w, a.w and www, each with an A RRset, so w.signed.example. is
	// an empty non-terminal. The specs hold its NSEC records, and NSEC3 records for the same names.
	Describe("the proof that a wildcard answers for a name", func() {
		var (
			signedSOA           []dns.RR
			apex, wild, aw, www []dns.RR // The NSEC records of the zone, in the order of its names
			encloser3, wild3    []dns.RR // The NSEC3 records of w.signed.example. and of *.w.signed.example.
		)

		// wildcardA returns the A RRset of *.w.signed.example. as it answers for owner
		wildcardA := func(owner string) []dns.RR {
			return expandedTo(owner, inChild(newRR("*.w."+child+" 300 IN A 192.0.2.1")))
		}
		// covering returns the NSEC3 record of signed.example. that covers the hash of name, and
		// optOut the same with the Opt-Out flag
		covering := func(name string) []dns.RR { return inChild(nsec3Range(child, name, -1, 1)) }
		optOut := func(name string) []dns.RR {
			rr := nsec3Range(child, name, -1, 1)
			rr.Flags = 1

			return inChild(rr)
		}

		BeforeEach(func() {
			signedSOA = inChild(soa(child))
			apex = inChild(newRR(child + " 300 IN NSEC *.w." + child + " NS SOA RRSIG NSEC DNSKEY"))
			wild = inChild(newRR("*.w." + child + " 300 IN NSEC a.w." + child + " A RRSIG NSEC"))
			aw = inChild(newRR("a.w." + child + " 300 IN NSEC www." + child + " A RRSIG NSEC"))
			www = inChild(newRR("www." + child + " 300 IN NSEC " + child + " A RRSIG NSEC"))
			encloser3 = inChild(nsec3Range(child, "w."+child, 0, 1))
			wild3 = inChild(nsec3Range(child, "*.w."+child, 0, 1, dns.TypeA, dns.TypeRRSIG))
		})

		It("is validated with the rest of the authority section", func() {
			// *.w.signed.example. answers for x.w.signed.example., which the NSEC record of
			// a.w.signed.example. covers, as an NSEC3 record covers its hash
			a := wildcardA("x.w." + child)
			nsec3 := covering("x.w." + child)
			cname := inParent(newRR("alias." + parent + " 300 IN CNAME x.w." + child))

			Expect(a[1].(*dns.RRSIG).Labels).Should(BeEquivalentTo(3), "the RRSIG is that of the wildcard")

			Expect(status(reply(noError, a, aw), "x.w."+child, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, a, nsec3), "x.w."+child, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, slices.Concat(cname, a), aw), "alias."+parent, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "behind a CNAME")

			Expect(status(reply(noError, a, badlySigned(aw)), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC record with an RRSIG that does not verify")
			Expect(status(reply(noError, a, badlySigned(nsec3)), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC3 record with an RRSIG that does not verify")
			Expect(status(reply(noError, slices.Concat(cname, a), aw[:1]), "alias."+parent, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC record without RRSIG behind a CNAME")
		})

		It("is needed for an RRset that an RRSIG made for the wildcard verifies (RFC 4035 §5.3.4)", func() {
			a := wildcardA("x.w." + child)
			cname := inParent(newRR("alias." + parent + " 300 IN CNAME x.w." + child))

			Expect(status(reply(noError, a, aw), "x.w."+child, dns.TypeA)).Should(Equal(ValidationResultSecure))

			Expect(status(reply(noError, a), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "no NSEC or NSEC3 record")
			Expect(status(reply(noError, a, signedSOA), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "the SOA record alone")
			Expect(status(reply(noError, slices.Concat(cname, a)), "alias."+parent, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "no NSEC or NSEC3 record behind a CNAME")
			Expect(status(reply(noError, a, www), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC record that does not cover the name")
			Expect(status(reply(noError, a, covering("z.w."+child)), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC3 record that covers another name")
			Expect(status(reply(noError, a, inParent(newRR("a.w."+child+" 300 IN NSEC www."+child+" A RRSIG NSEC"))),
				"x.w."+child, dns.TypeA)).Should(Equal(ValidationResultBogus), "NSEC record that the zone above signed")
		})

		It("gives the RRset its status, which is Bogus until then", func() {
			budgeted := withQueryBudget(ctx, 30)
			keys := chainKeys{v: v}
			authority := validateSection(budgeted, aw, keys)

			answer := validateSection(budgeted, wildcardA("x.w."+child), keys)
			Expect(worstStatus(answer)).Should(Equal(ValidationResultBogus))

			v.proveExpansions(budgeted, authority, answer)
			Expect(worstStatus(answer)).Should(Equal(ValidationResultSecure))

			// The zone signed the RRset of the wildcard and none of the name, so an NSEC record that
			// the wildcard gives the name is no denial of the zone, with the proof either
			denial := validateSection(budgeted, expandedTo("x.w."+child, wild), keys)
			v.proveExpansions(budgeted, authority, denial)
			Expect(worstStatus(denial)).Should(Equal(ValidationResultSecure))
			Expect(denial[0].signer()).Should(BeEmpty())

			_, found := v.denialZone(denial, "x.w."+child)
			Expect(found).Should(BeFalse())
		})

		It("shows that the wildcard is the one at the closest encloser of the name (RFC 4592 §3.3.1)", func() {
			// The next closer name of y.x.w.signed.example. below w.signed.example. is
			// x.w.signed.example.: no name between the wildcard's and the name exists without it
			deep := wildcardA("y.x.w." + child)

			Expect(status(reply(noError, deep, aw), "y.x.w."+child, dns.TypeA)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, deep, covering("x.w."+child)), "y.x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "NSEC3 record that covers the next closer name")
			Expect(status(reply(noError, deep, covering("y.x.w."+child)), "y.x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC3 record that covers the name and not the next closer name")

			// With b.x.w.signed.example. the name x.w.signed.example. exists, and the wildcard answers
			// for no name below it
			closer := inChild(newRR("b.x.w." + child + " 300 IN NSEC www." + child + " A RRSIG NSEC"))
			Expect(status(reply(noError, wildcardA("c.x.w."+child), closer), "c.x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC record that shows a longer closest encloser")

			// A record from the apex to www says that the zone has no name below w.signed.example.
			none := inChild(newRR(child + " 300 IN NSEC www." + child + " NS SOA RRSIG NSEC DNSKEY"))
			Expect(status(reply(noError, wildcardA("x.w."+child), none), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC record that shows a shorter closest encloser")
		})

		It("is Insecure with an Opt-Out record that covers the next closer name (RFC 5155 §9.2)", func() {
			// The name may be an insecure delegation that Opt-Out leaves out of the NSEC3 chain, or a
			// name below one
			a := wildcardA("x.w." + child)
			cname := inParent(newRR("alias." + parent + " 300 IN CNAME x.w." + child))

			Expect(status(reply(noError, a, optOut("x.w."+child)), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultInsecure))
			Expect(status(reply(noError, slices.Concat(cname, a), optOut("x.w."+child)), "alias."+parent, dns.TypeA)).
				Should(Equal(ValidationResultInsecure), "behind a CNAME")
			Expect(status(reply(noError, nil, signedSOA, encloser3, optOut("x.w."+child), wild3), "x.w."+child, dns.TypeTXT)).
				Should(Equal(ValidationResultInsecure), "no data by the record of the wildcard")
		})

		It(`is needed for "no data" by the record of the wildcard (RFC 4035 §3.1.3.4, RFC 5155 §8.7)`, func() {
			nextCloser := covering("x.w." + child)

			Expect(status(reply(noError, nil, signedSOA, aw, wild), "x.w."+child, dns.TypeTXT)).
				Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, nil, signedSOA, encloser3, nextCloser, wild3), "x.w."+child, dns.TypeTXT)).
				Should(Equal(ValidationResultSecure), "NSEC3")

			Expect(status(reply(noError, nil, signedSOA, wild), "x.w."+child, dns.TypeTXT)).
				Should(Equal(ValidationResultBogus), "NSEC record of the wildcard alone")
			Expect(status(reply(noError, nil, signedSOA, encloser3, wild3), "x.w."+child, dns.TypeTXT)).
				Should(Equal(ValidationResultBogus), "NSEC3 records without the one that covers the next closer name")
			Expect(status(reply(noError, nil, signedSOA, aw, wild), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC record of the wildcard has the type")
			Expect(status(reply(noError, nil, signedSOA, encloser3, nextCloser, wild3), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "NSEC3 record of the wildcard has the type")
		})

		It("is needed, with the denial of the wildcard, for a name error (RFC 4035 §5.4)", func() {
			// zz.signed.example. is after the last name of the zone, and the wildcard that would
			// answer for it, *.signed.example., between the apex and the first name
			Expect(status(reply(nameError, nil, signedSOA, www, apex), "zz."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure))
			Expect(status(reply(nameError, nil, signedSOA, apex), "nx."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "one record covers the name and the wildcard")

			Expect(status(reply(nameError, nil, signedSOA, www), "zz."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "no record covers the wildcard")
			Expect(status(reply(nameError, nil, signedSOA, apex), "zz."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "no record covers the name")
			Expect(status(reply(nameError, nil, signedSOA, aw, apex), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "the wildcard at the closest encloser exists")
			Expect(status(reply(nameError, nil, signedSOA, apex), "w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "the name is an empty non-terminal")
		})

		It("takes a wildcard that is an empty non-terminal for a name that exists (RFC 4592 §4.9)", func() {
			// Here the zone has the name sub.*.signed.example. alone. *.signed.example. has no
			// records and a name below it: it answers for x.signed.example., with no data.
			first := inChild(newRR(child + " 300 IN NSEC sub.*." + child + " NS SOA RRSIG NSEC DNSKEY"))
			last := inChild(newRR("sub.*." + child + " 300 IN NSEC " + child + " TXT RRSIG NSEC"))

			Expect(status(reply(noError, nil, signedSOA, last, first), "x."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "no data")
			Expect(status(reply(nameError, nil, signedSOA, last, first), "x."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name error")
			Expect(status(reply(noError, nil, signedSOA, last), "x."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "no data without the record that shows the wildcard")

			// The NSEC3 record of an empty non-terminal lists no type
			apex3 := inChild(nsec3Range(child, child, 0, 1, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY))
			empty := inChild(nsec3Range(child, "*."+child, 0, 1))

			Expect(status(reply(noError, nil, signedSOA, apex3, covering("x."+child), empty), "x."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "no data, NSEC3")
			Expect(status(reply(nameError, nil, signedSOA, apex3, covering("x."+child), empty), "x."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name error, NSEC3")
		})

		It("takes no record that the zone did not sign for its owner name (RFC 4035 §5.4)", func() {
			// Here the zone has the names *, mail and www. The RRSIG of the NSEC record of
			// *.signed.example. verifies the record under every name that the wildcard matches.
			wildcard := inChild(newRR("*." + child + " 300 IN NSEC mail." + child + " TXT RRSIG NSEC"))
			mail := inChild(newRR("mail." + child + " 300 IN NSEC www." + child + " MX RRSIG NSEC"))

			Expect(status(reply(noError, nil, signedSOA, mail), "mail."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure))

			Expect(status(reply(nameError, nil, signedSOA, mail, expandedTo("n."+child, wildcard)), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "name error for a name that exists")
			Expect(status(reply(noError, nil, signedSOA, mail, expandedTo("n."+child, wildcard),
				expandedTo("www."+child, wildcard)), "www."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "no data for a type that the name has")
			Expect(status(reply(noError, expandedTo("x."+child, inChild(newRR("*."+child+` 300 IN TXT "v=1"`))),
				expandedTo("x."+child, wildcard)), "x."+child, dns.TypeTXT)).
				Should(Equal(ValidationResultBogus), "the record of the wildcard as the proof for its own expansion")
		})

		It("has no DS RRset for a name (RFC 4592 §4.6)", func() {
			// Here the zone has the names * and z. x.signed.example. does not exist, and the NSEC
			// record of the wildcard covers it.
			wildcard := inChild(newRR("*." + child + " 300 IN NSEC z." + child + " TXT DS RRSIG NSEC"))
			txt := expandedTo("x."+child, inChild(newRR("*."+child+` 300 IN TXT "v=1"`)))
			ds := expandedTo("x."+child, inChild(newRR("*."+child+" 300 IN DS 12345 13 2 "+strings.Repeat("00", 32))))

			Expect(status(reply(noError, txt, wildcard), "x."+child, dns.TypeTXT)).Should(Equal(ValidationResultSecure))
			Expect(status(reply(noError, ds, wildcard), "x."+child, dns.TypeDS)).Should(Equal(ValidationResultBogus))
			Expect(status(reply(noError, ds), "x."+child, dns.TypeDS)).
				Should(Equal(ValidationResultBogus), "without the proof")
		})

		It("is read from the records of the zone of the wildcard, whatever other zones add to the reply", func() {
			// *.w.signed.example. is a CNAME to nx.example., a name that does not exist. The NSEC3
			// chain of signed.example. has no salt, and that of example. has one.
			cname := expandedTo("x.w."+child, inChild(newRR("*.w."+child+" 300 IN CNAME nx."+parent)))
			salted := func(name string, from int64, types ...uint16) []dns.RR {
				return inParent(nsec3SaltedRange(parent, name, "ab", 1, from, 1, types...))
			}
			denial := slices.Concat(inParent(soa(parent)),
				salted(parent, 0, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM),
				salted("nx."+parent, -1), salted("*."+parent, -1))

			Expect(status(reply(nameError, cname, covering("x.w."+child), denial), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure))
			Expect(status(reply(nameError, cname, denial, covering("x.w."+child)), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultSecure), "records in another order")
			Expect(status(reply(nameError, cname, denial), "x.w."+child, dns.TypeA)).
				Should(Equal(ValidationResultBogus), "without the record of the zone of the wildcard")
		})

		// Replies as resolvers send them for names that wildcards answer for, with their names
		// under signed.example.
		It("holds for the replies that zones with wildcards send", func() {
			sub := func(name string) string { return name + "." + child }
			nsec := func(owner, next, types string) []dns.RR {
				return inChild(newRR(owner + " 300 IN NSEC " + next + " " + types))
			}

			// A CNAME of *.pages for a name two labels below pages, with the one NSEC3 record that
			// covers the next closer name b.pages
			deep := slices.Concat(
				expandedTo(sub("a.b.pages"), inChild(newRR(sub("*.pages")+" 300 IN CNAME "+sub("fastly")))),
				inChild(newRR(sub("fastly")+" 300 IN A 192.0.2.1")))
			Expect(status(reply(noError, deep, covering(sub("b.pages"))), sub("a.b.pages"), dns.TypeA)).
				Should(Equal(ValidationResultSecure), "wildcard answer two labels below the wildcard, NSEC3")

			// A CNAME of *.id with the NSEC record of the wildcard itself, the name before the name
			// asked for
			expanded := slices.Concat(
				expandedTo(sub("zz9xqq.id"), inChild(newRR(sub("*.id")+" 300 IN CNAME "+sub("wildcard")))),
				inChild(newRR(sub("wildcard")+" 300 IN A 192.0.2.1")))
			Expect(status(reply(noError, expanded, nsec(sub("*.id"), sub("infrastructure"), "CNAME RRSIG NSEC")),
				sub("zz9xqq.id"), dns.TypeA)).Should(Equal(ValidationResultSecure), "wildcard answer by the NSEC record of the wildcard")

			// A name error by the last NSEC record of the zone, which a wildcard below the apex owns,
			// and the record of the apex
			Expect(status(reply(nameError, nil, signedSOA, nsec(sub("*.p"), child, "TXT RRSIG NSEC"),
				nsec(child, sub("_dmarc"), "A NS SOA TXT AAAA RRSIG NSEC DNSKEY")), sub("www"), dns.TypeA)).
				Should(Equal(ValidationResultSecure), "name error by the NSEC record of a wildcard")

			// No data by the NSEC record of *.signed.example. and the last record of the zone
			Expect(status(reply(noError, nil, signedSOA, nsec(sub("*"), sub("batch._dane"), "TXT RRSIG NSEC"),
				nsec(sub("_443._tcp.www"), child, "CNAME RRSIG NSEC")), sub("zz9x"), dns.TypeA)).
				Should(Equal(ValidationResultSecure), "no data by the NSEC record of the wildcard")

			// A CNAME of the zone above to a name that *.signed.example. answers for, without the type
			alias := func(target string) []dns.RR { return inParent(newRR("www." + parent + " 300 IN CNAME " + target)) }
			Expect(status(reply(noError, alias(sub("nasa")), signedSOA, nsec(sub("lotus"), sub("ns1"), "A RRSIG NSEC"),
				nsec(sub("*"), sub("_acme-challenge"), "A AAAA RRSIG NSEC")), "www."+parent, dns.TypeHTTPS)).
				Should(Equal(ValidationResultSecure), "no data behind a CNAME")
			Expect(status(reply(noError, alias(sub("harvard")), nsec(sub("*"), sub("_acme-challenge"), "A AAAA RRSIG NSEC"),
				nsec(sub("_psl"), sub("lotus"), "TXT RRSIG NSEC"), signedSOA), "www."+parent, dns.TypeHTTPS)).
				Should(Equal(ValidationResultSecure), "no data behind a CNAME, records in another order")
		})
	})

	// RFC 8914: a Bogus reply is told with the extended DNS error of the RRset that decided its
	// status. That says more than "DNSSEC Bogus" if every try at the RRset failed for one thing
	// that has a code of its own.
	Describe("what a client is told of a Bogus reply", func() {
		var (
			question dns.Question
			a        []dns.RR // www.signed.example. A with its RRSIG
		)

		// during returns rrset followed by the RRSIG that signed.example. makes for it with a
		// validity period that begins at from and ends at until, as offsets from now
		during := func(rrset []dns.RR, from, until time.Duration) []dns.RR {
			sig := signRRsetDuring(rrset, rrset[0].Header().Rrtype, chain.childKey, chain.childPriv, child, from, until)

			return append(slices.Clone(rrset), sig)
		}
		// signedWith returns the RRSIG of a as one that names key
		signedWith := func(key *dns.DNSKEY) *dns.RRSIG {
			sig, _ := dns.Copy(a[1]).(*dns.RRSIG)
			sig.Algorithm, sig.KeyTag = key.Algorithm, key.KeyTag()

			return sig
		}
		// serveKeys makes keys, followed by their RRSIG, the reply to the DNSKEY query for
		// signed.example.
		serveKeys := func(keys []dns.RR) {
			resolve := upstream.ResolveFn
			upstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				if q := req.Req.Question[0]; q.Qtype == dns.TypeDNSKEY && q.Name == child {
					return &model.Response{Res: &dns.Msg{Answer: keys}}, nil
				}

				return resolve(ctx, req)
			}
		}
		told := func(answer ...dns.RR) Verdict {
			return v.Validate(ctx, reply(noError, answer), question)
		}
		beTold := func(ede uint16, text string) OmegaMatcher {
			return SatisfyAll(HaveField("Result", ValidationResultBogus), HaveField("EDE", ede),
				HaveField("Text", HavePrefix(text)))
		}

		const (
			expired     = dns.ExtendedErrorCodeSignatureExpired
			notYetValid = dns.ExtendedErrorCodeSignatureNotYetValid
			noSupport   = dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm
			dnssecBogus = dns.ExtendedErrorCodeDNSBogus
		)

		BeforeEach(func() {
			question = dns.Question{Name: "www." + child, Qtype: dns.TypeA, Qclass: dns.ClassINET}
			a = inChild(newRR(question.Name + " 300 IN A 192.0.2.1"))
		})

		It("says that the signatures have expired, or are not yet valid, if that holds for all of them", func() {
			past := during(a[:1], -48*time.Hour, -24*time.Hour)
			future := during(a[:1], 24*time.Hour, 48*time.Hour)

			Expect(told(past...)).Should(beTold(expired, "signature expired"))
			Expect(told(future...)).Should(beTold(notYetValid, "signature not yet valid"))
			Expect(told(append(past, during(a[:1], -72*time.Hour, -48*time.Hour)[1])...)).
				Should(beTold(expired, "signature expired"), "two RRSIGs that have expired")

			// An RRSIG within its validity period that does not verify is no expired one
			Expect(told(append(past, badlySigned(a)[1])...)).
				Should(beTold(dnssecBogus, question.Name+" A failed validation"))

			// Only a signature that the key made says that it has expired, or is not yet valid: a
			// made-up one with such dates is a failed signature
			Expect(told(badlySigned(past)...)).Should(beTold(dnssecBogus, question.Name+" A failed validation"))
			Expect(told(badlySigned(future)...)).Should(beTold(dnssecBogus, question.Name+" A failed validation"))
		})

		It("says so if the zone keys are the RRset whose signatures have expired", func() {
			serveKeys(during([]dns.RR{chain.childKey}, -48*time.Hour, -24*time.Hour))

			Expect(told(a...)).Should(beTold(expired, "signature expired"))
		})

		It("says that the algorithm is not supported if nothing here verifies with any key that an RRSIG names", func() {
			// The zone has a key of an algorithm that is not implemented, and an RSA/SHA-1 key with an
			// exponent that nothing verifies with
			gost := *chain.childKey
			gost.Algorithm = dns.ECCGOST
			unusable, _, _, _ := generateBigExponentRSAKey(child)
			unusable.Algorithm = dns.RSASHA1

			serveKeys(inChild(chain.childKey, &gost, unusable))

			Expect(told(a[0], signedWith(&gost))).Should(beTold(noSupport, "unsupported DNSSEC algorithm: 12"))
			Expect(told(a[0], signedWith(unusable))).
				Should(beTold(noSupport, fmt.Sprintf("no support for the RSA exponent of DNSKEY %d", unusable.KeyTag())))
			Expect(told(a[0], signedWith(&gost), signedWith(unusable))).
				Should(beTold(noSupport, "no support for the RSA exponent"), "both, the RRSIG of the RSA key first")

			// An RRSIG of a key that verifies, and does not, leaves no RRset of such keys only
			Expect(told(a[0], signedWith(&gost), badlySigned(a)[1])).
				Should(beTold(dnssecBogus, question.Name+" A failed validation"))
		})
	})
})
