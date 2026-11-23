package dnssec

import (
	"context"
	"slices"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// What validation has verified holds no longer than the records that proved it are authentic. An
// RRset is authentic for the TTL that its zone gave it and until the RRSIG that verified it
// expires: no longer than its TTL in the reply, the TTL of the RRSIG, the Original TTL field of the
// RRSIG and the time until the RRSIG expires (RFC 4035 §5.3.3), and one that a wildcard answers
// with no longer than the proof of that (RFC 9077 §4.1). A zone is Secure or Insecure, and a name
// is no zone cut, for as long as the DS RRset, the DNSKEY RRset or the denial that proved it
// (RFC 2308 §5 and RFC 9077 §3.4 for a denial).
//
// example. is the trust anchor and delegates the signed zone signed.example. The cache of zones of
// the validator has a clock that stands still unless a spec moves it (uniClock).
var _ = Describe("Lifetime of what validation verified", func() {
	// What ends the lifetime of an RRset
	type bound int

	const (
		rrsetTTL    bound = iota // The TTL of its records in the reply
		rrsigTTL                 // The TTL of its RRSIG in the reply
		originalTTL              // The Original TTL field of its RRSIG
		expiration               // The time until its RRSIG expires
	)

	var (
		ctx   context.Context
		c     *repliedChain
		clock *uniClock
		v     *Validator
	)

	// validator returns a validator for the zones of c whose cache of zones is clock
	validator := func(anchors *TrustAnchorStore, maxChainDepth uint) *Validator {
		logger, _ := log.NewMockEntry()
		v := NewValidator(ctx, anchors, logger, &mockResolver{ResolveFn: c.resolve}, 1, maxChainDepth, 150, 30, 3600)
		v.validationCache = clock

		return v
	}

	// signed returns rrset followed by the RRSIG that example. makes for it. Each of the four values
	// lets the RRset be authentic for five minutes.
	signed := func(rrset ...dns.RR) []dns.RR {
		for _, rr := range rrset {
			rr.Header().Ttl = 300
		}

		return append(slices.Clone(rrset), signRRset(rrset, rrset[0].Header().Rrtype, c.parentKey, c.parentPriv, c.parent))
	}

	// resigned returns rrs, an RRset followed by its RRSIG as signed returns them, after change and
	// with the signature that example. then makes: an RRSIG covers its Original TTL field and its
	// expiration, and no TTL of the reply
	resigned := func(rrs []dns.RR, change func(sig *dns.RRSIG)) []dns.RR {
		sig, _ := rrs[len(rrs)-1].(*dns.RRSIG)
		change(sig)
		Expect(sig.Sign(c.parentPriv, rrs[:len(rrs)-1])).Should(Succeed())

		return rrs
	}

	// lasting is signed for an RRset that the value by lets be authentic for one minute only
	lasting := func(by bound, rrset ...dns.RR) []dns.RR {
		return resigned(signed(rrset...), func(sig *dns.RRSIG) {
			switch by {
			case rrsetTTL:
				for _, rr := range rrset {
					rr.Header().Ttl = 60
				}
			case rrsigTTL:
				sig.Hdr.Ttl = 60
			case originalTTL:
				sig.OrigTtl = 60
			case expiration:
				sig.Expiration = uint32(time.Now().Add(time.Minute).Unix())
			}
		})
	}

	// expired is signed for an RRset whose RRSIG expired a minute ago, which the clock skew
	// tolerance of an hour lets verify
	expired := func(rrset ...dns.RR) []dns.RR {
		return resigned(signed(rrset...), func(sig *dns.RRSIG) {
			sig.Expiration = uint32(time.Now().Add(-time.Minute).Unix())
		})
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

	newRR := func(s string) dns.RR {
		rr, err := dns.NewRR(s)
		Expect(err).Should(Succeed())

		return rr
	}

	ttls := func(rrs []dns.RR) []uint32 {
		out := make([]uint32, len(rrs))
		for i, rr := range rrs {
			out[i] = rr.Header().Ttl
		}

		return out
	}

	BeforeEach(func(specCtx SpecContext) {
		ctx = withQueryBudget(specCtx, 30)
		c = newRepliedChain()
		clock = &uniClock{entries: map[string]uniClockEntry{}}
		v = validator(c.anchors, 10)
	})

	Describe("an RRset of a reply", func() {
		question := dns.Question{Name: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		expanded := dns.Question{Name: "x.w.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

		DescribeTable("is authentic for as long as the RRSIG that verified it allows (RFC 4035 §5.3.3)",
			func(by bound) {
				reply := &dns.Msg{Answer: lasting(by, newRR("www.example. A 192.0.2.1"))}
				sent := ttls(reply.Answer)

				verdict := v.Validate(ctx, reply, question)
				Expect(verdict.Result).Should(Equal(ValidationResultSecure))

				// The RRSIG has the TTL of the RRset that it covers
				for _, ttl := range ttls(verdict.Lifetimes.Bound(reply.Answer)) {
					Expect(ttl).Should(And(BeNumerically("<=", 60), BeNumerically(">", 50)))
				}

				Expect(ttls(reply.Answer)).Should(Equal(sent), "the reply stays as it is")
			},
			Entry("no longer than the TTL of its records", rrsetTTL),
			Entry("no longer than the TTL of the RRSIG", rrsigTTL),
			Entry("no longer than the Original TTL field of the RRSIG", originalTTL),
			Entry("no longer than the time until the RRSIG expires", expiration),
		)

		It("is authentic no longer if its RRSIG has expired and verifies within the clock skew tolerance", func() {
			reply := &dns.Msg{Answer: expired(newRR("www.example. A 192.0.2.1"))}

			verdict := v.Validate(ctx, reply, question)
			Expect(verdict.Result).Should(Equal(ValidationResultSecure))
			Expect(ttls(verdict.Lifetimes.Bound(reply.Answer))).Should(Equal([]uint32{0, 0}))
		})

		It("has its lifetime from the RRSIG that verified it, whatever another one says that covers it", func() {
			// An RRSIG that names the key of example. and does not verify, with the Original TTL 1
			answer := lasting(originalTTL, newRR("www.example. A 192.0.2.1"))
			other, _ := dns.Copy(answer[1]).(*dns.RRSIG)
			other.OrigTtl = 1
			reply := &dns.Msg{Answer: []dns.RR{answer[0], other, answer[1]}}

			verdict := v.Validate(ctx, reply, question)
			Expect(verdict.Result).Should(Equal(ValidationResultSecure))
			Expect(ttls(verdict.Lifetimes.Bound(reply.Answer))).Should(Equal([]uint32{60, 60, 60}))
		})

		It("has the lifetime that its own RRSIG gives it, also if a wildcard answers with it", func() {
			// *.w.example. answers for x.w.example., which the NSEC record of a.w.example. covers.
			// example. signed the wildcard RRset for a minute, and the NSEC record for five.
			a := expandedTo(expanded.Name, lasting(originalTTL, newRR("*.w.example. A 192.0.2.1")))
			reply := &dns.Msg{Answer: a, Ns: signed(newRR("a.w.example. NSEC www.example. A RRSIG NSEC"))}

			verdict := v.Validate(ctx, reply, expanded)
			Expect(verdict.Result).Should(Equal(ValidationResultSecure))
			Expect(ttls(verdict.Lifetimes.Bound(reply.Answer))).Should(Equal([]uint32{60, 60}))
			Expect(ttls(verdict.Lifetimes.Bound(reply.Ns))).Should(Equal([]uint32{300, 300}))
		})

		DescribeTable("that a wildcard answers with is authentic no longer than the proof of that (RFC 9077 §4.1)",
			func(proof func() dns.RR) {
				// example. signed the RRset of *.w.example. for five minutes, and the record that
				// shows that no closer name than the wildcard answers for x.w.example. for one
				a := expandedTo(expanded.Name, signed(newRR("*.w.example. A 192.0.2.1")))
				reply := &dns.Msg{Answer: a, Ns: lasting(originalTTL, proof())}

				verdict := v.Validate(ctx, reply, expanded)
				Expect(verdict.Result).Should(Equal(ValidationResultSecure))
				Expect(ttls(verdict.Lifetimes.Bound(reply.Answer))).Should(Equal([]uint32{60, 60}))
				Expect(ttls(verdict.Lifetimes.Bound(reply.Ns))).Should(Equal([]uint32{60, 60}))
			},
			Entry("an NSEC record that covers the name",
				func() dns.RR { return newRR("a.w.example. NSEC www.example. A RRSIG NSEC") }),
			Entry("an NSEC3 record that covers the next closer name",
				func() dns.RR { return nsec3Range("example.", "x.w.example.", -1, 1) }),
		)
	})

	Describe("what the chain of trust walk found at a name", func() {
		const name = "name.example."

		// The replies that make a name of example. what the walk finds it to be, with the RRset
		// that proves it authentic as lasting makes it
		nsec := func(types string) func(name string, by bound) {
			return func(name string, by bound) {
				c.replies["DS "+name] = &dns.Msg{Ns: lasting(by, newRR(name+" NSEC \\000."+name+" "+types+" RRSIG NSEC"))}
			}
		}
		nsec3 := func(types ...uint16) func(name string, by bound) {
			return func(name string, by bound) {
				c.replies["DS "+name] = &dns.Msg{Ns: lasting(by, nsec3Range(c.parent, name, 0, 1, types...))}
			}
		}
		alias := func(name string, by bound) {
			c.replies["DS "+name] = &dns.Msg{Answer: lasting(by, newRR(name+" CNAME www.example."))}
		}
		secureZone := func(name string, by bound) {
			key, priv, _ := newSignedZoneKey(name)
			c.replies["DS "+name] = &dns.Msg{Answer: lasting(by, key.ToDS(dns.SHA256))}
			c.replies["DNSKEY "+name] = &dns.Msg{Answer: []dns.RR{
				key, signRRset([]dns.RR{key}, dns.TypeDNSKEY, key, priv, name),
			}}
		}
		// A zone whose DS RRset names a key that nothing verifies with: RSA/SHA-1, exponent 2^32+1
		zoneWithoutUsableKey := func(name string, by bound) {
			key, _, _, _ := generateBigExponentRSAKey(name)
			key.Algorithm = dns.RSASHA1
			c.replies["DS "+name] = &dns.Msg{Answer: lasting(by, key.ToDS(dns.SHA256))}
			c.replies["DNSKEY "+name] = &dns.Msg{Answer: []dns.RR{key}}
		}

		// keptForAMinute walks to the name three times: when the cache of zones has nothing for it,
		// 50 seconds later and 70 seconds later
		keptForAMinute := func(expected ValidationResult) {
			Expect(v.walk(ctx, name, false).result).Should(Equal(expected))
			Expect(c.queries).Should(ContainElement("DS " + name))

			c.queries = nil
			clock.now += 50 * time.Second

			Expect(v.walk(ctx, name, false).result).Should(Equal(expected))
			Expect(c.queries).Should(BeEmpty(), "the cache of zones holds the name while the proof is authentic")

			clock.now += 20 * time.Second

			Expect(v.walk(ctx, name, false).result).Should(Equal(expected))
			Expect(c.queries).Should(ContainElement("DS "+name), "and no longer")
		}

		DescribeTable("is kept until the RRset that proved it ends",
			func(prove func(name string, by bound), by bound, expected ValidationResult) {
				prove(name, by)
				keptForAMinute(expected)
			},
			Entry("an insecure delegation, with the TTL of the NSEC record that denies its DS RRset",
				nsec("NS"), rrsetTTL, ValidationResultInsecure),
			Entry("an insecure delegation, with the TTL of the RRSIG of that record",
				nsec("NS"), rrsigTTL, ValidationResultInsecure),
			Entry("an insecure delegation, with the Original TTL of the RRSIG of that record",
				nsec("NS"), originalTTL, ValidationResultInsecure),
			Entry("an insecure delegation, when the RRSIG of that record expires",
				nsec("NS"), expiration, ValidationResultInsecure),
			Entry("an insecure delegation, with the TTL of the NSEC3 record that denies its DS RRset",
				nsec3(dns.TypeNS), rrsetTTL, ValidationResultInsecure),
			Entry("a name that is no zone cut, with the TTL of the NSEC record that shows it",
				nsec("A"), rrsetTTL, ValidationResultSecure),
			Entry("a name that is no zone cut, when the RRSIG of that record expires",
				nsec("A"), expiration, ValidationResultSecure),
			Entry("a name that is no zone cut, with the Original TTL of the RRSIG of the NSEC3 record that shows it",
				nsec3(dns.TypeA, dns.TypeRRSIG), originalTTL, ValidationResultSecure),
			Entry("a name that is no zone cut, with the Original TTL of the RRSIG of the CNAME RRset that it owns",
				alias, originalTTL, ValidationResultSecure),
			Entry("a secure zone, with the TTL of its DS RRset",
				secureZone, rrsetTTL, ValidationResultSecure),
			Entry("a zone that is Insecure for its unusable key, with the TTL of the DS RRset that names it",
				zoneWithoutUsableKey, rrsetTTL, ValidationResultInsecure),
		)

		It("is kept until the first NSEC RRset of the denial ends, whichever of them the proof reads", func() {
			// The NSEC record of the delegation, which example. signed for five minutes, after
			// another NSEC record of example., which it signed for one
			c.replies["DS "+name] = &dns.Msg{Ns: slices.Concat(
				lasting(originalTTL, newRR("aaa.example. NSEC bbb.example. A RRSIG NSEC")),
				signed(newRR(name+" NSEC \\000."+name+" NS RRSIG NSEC")),
			)}

			keptForAMinute(ValidationResultInsecure)
		})

		It("is not kept if the RRSIG of its proof has expired and verifies within the clock skew tolerance", func() {
			c.replies["DS "+name] = &dns.Msg{Ns: expired(newRR(name + " NSEC \\000." + name + " NS RRSIG NSEC"))}

			for range 2 {
				c.queries = nil

				Expect(v.walk(ctx, name, false).result).Should(Equal(ValidationResultInsecure))
				Expect(c.queries).Should(ContainElement("DS " + name))
			}
		})

		It("gives way to a newly delegated zone once the proof that the name was no zone cut has ended", func() {
			nsec("A")(name, rrsetTTL)
			Expect(v.walk(ctx, name, true).result).Should(Equal(ValidationResultBogus), "a name inside example. is no signer")

			key, _ := c.delegate(c.parent, c.parentKey, c.parentPriv, name)
			clock.now += 50 * time.Second

			Expect(v.walk(ctx, name, true).result).Should(Equal(ValidationResultBogus), "the proof is still authentic")

			clock.now += 20 * time.Second

			zone := v.walk(ctx, name, true)
			Expect(zone.result).Should(Equal(ValidationResultSecure))
			Expect(zone.keys).Should(ConsistOf(key))
		})

		It("gives way to a newly signed zone once the denial of its DS RRset has ended", func() {
			nsec("NS")(name, rrsetTTL)
			Expect(v.walk(ctx, name, true).result).Should(Equal(ValidationResultInsecure))

			key, _ := c.delegate(c.parent, c.parentKey, c.parentPriv, name)
			clock.now += 50 * time.Second

			Expect(v.walk(ctx, name, true).result).Should(Equal(ValidationResultInsecure), "the denial is still authentic")

			clock.now += 20 * time.Second

			zone := v.walk(ctx, name, true)
			Expect(zone.result).Should(Equal(ValidationResultSecure))
			Expect(zone.keys).Should(ConsistOf(key))
		})
	})

	// A zone is what the cache of zones holds for it until its own proof ends, so a walk needs
	// nothing from the zones above it. Here the keys of example. are authentic for a minute, and
	// the lookup of them fails after that.
	Describe("a zone that the cache of zones holds", func() {
		BeforeEach(func() {
			c.replies["DNSKEY "+c.parent] = &dns.Msg{Answer: lasting(rrsetTTL, c.parentKey)}
		})

		// loseParent lets the cache entry of example. end and the upstream fail to answer for its keys
		loseParent := func() {
			clock.now += 70 * time.Second
			c.replies["DNSKEY "+c.parent] = nil
			c.queries = nil
		}

		It("answers for the names below it without a query if it is an insecure delegation", func() {
			// island.insecure.example. has a trust anchor of its own
			const (
				insecure = "insecure.example."
				island   = "island." + insecure
			)

			islandKey, islandPriv, anchor := newSignedZoneKey(island)
			anchors, err := NewTrustAnchorStore([]string{c.parentKey.String(), anchor})
			Expect(err).Should(Succeed())

			v = validator(anchors, 10)
			c.replies["DS "+insecure] = &dns.Msg{Ns: c.parentNSEC(insecure, dns.TypeNS)}
			c.replies["DNSKEY "+island] = &dns.Msg{Answer: []dns.RR{
				islandKey, signRRset([]dns.RR{islandKey}, dns.TypeDNSKEY, islandKey, islandPriv, island),
			}}

			Expect(v.walk(ctx, "www."+insecure, false).result).Should(Equal(ValidationResultInsecure))
			Expect(c.queries).Should(Equal([]string{"DNSKEY " + c.parent, "DS " + insecure}))

			loseParent()

			Expect(v.walk(ctx, "a.b."+insecure, false).result).Should(Equal(ValidationResultInsecure))
			Expect(c.queries).Should(BeEmpty())

			// No walk starts above the closest trust anchor
			zone := v.walk(ctx, island, true)
			Expect(zone.result).Should(Equal(ValidationResultSecure))
			Expect(zone.keys).Should(ConsistOf(islandKey))
			Expect(c.queries).Should(Equal([]string{"DNSKEY " + island}))
		})

		DescribeTable("is where the walk to a zone below it starts if it is secure",
			func(maxChainDepth uint, expected ValidationResult) {
				// signed.example. is the first zone below the trust anchor, deep.signed.example. the second
				grandchild := "deep." + c.child
				c.delegate(c.child, c.childKey, c.childPriv, grandchild)
				v = validator(c.anchors, maxChainDepth)

				Expect(v.walk(ctx, c.child, true).result).Should(Equal(ValidationResultSecure))

				loseParent()

				Expect(v.walk(ctx, grandchild, true).result).Should(Equal(expected))
				Expect(c.queries).Should(Equal([]string{"DS " + grandchild, "DNSKEY " + grandchild}))
			},
			Entry("with its keys, which validate the zone below", uint(10), ValidationResultSecure),
			Entry("as a zone of the chain, which has the zones above it too", uint(1), ValidationResultBogus),
		)

		It("leaves a walk that fails below it incomplete, with what could not be looked up", func() {
			// The lookup of the DS RRset of deep.signed.example. fails
			grandchild := "deep." + c.child
			c.replies["DS "+grandchild] = nil

			Expect(v.walk(ctx, c.child, true).result).Should(Equal(ValidationResultSecure))

			loseParent()

			zone := v.walk(ctx, grandchild, true)
			Expect(zone.result).Should(Equal(ValidationResultIndeterminate))
			Expect(zone.err).Should(MatchError(errNoReply))
			Expect(c.queries).Should(Equal([]string{"DS " + grandchild}))

			// Under the trust anchor that leaves the data of a reply unvalidated, which is Bogus
			unsigned := &dns.Msg{Answer: []dns.RR{newRR("www." + grandchild + " A 192.0.2.1")}}
			Expect(v.ValidateResponse(ctx, unsigned, dns.Question{
				Name: "www." + grandchild, Qtype: dns.TypeA, Qclass: dns.ClassINET,
			})).Should(Equal(ValidationResultBogus))
		})
	})
})
