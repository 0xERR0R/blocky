package dnssec

import (
	"context"
	"net"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// A name with a trust anchor above it is in a secure part of the tree until a verified denial says
// otherwise. If the records that validate a reply for it cannot be obtained, for whatever reason,
// the reply is not validated and is Bogus (RFC 4035 §5.5). A name without a trust anchor above it
// is Indeterminate (RFC 4033 §5).
//
// example. is the trust anchor. It delegates the signed zone signed.example., which holds
// www.signed.example. A. A lookup of the chain of trust walk cannot be completed when it gets no
// reply, a truncated reply, a reply with an error RCODE, a reply without the DNSKEY RRset of the
// zone or, for a DS RRset, a reply without that RRset and without its denial.
var _ = Describe("Validation that cannot be completed", func() {
	const (
		noReachableAuthority = dns.ExtendedErrorCodeNoReachableAuthority
		networkError         = dns.ExtendedErrorCodeNetworkError
		dnskeyMissing        = dns.ExtendedErrorCodeDNSKEYMissing
		nsecMissing          = dns.ExtendedErrorCodeNSECMissing
	)

	var (
		ctx      context.Context
		c        *repliedChain
		upstream *mockResolver
		v        *Validator
		question dns.Question
		signed   *dns.Msg // www.signed.example. A with the RRSIG of signed.example.
		unsigned *dns.Msg // The same RRset without RRSIG

		// once maps "TYPE name" to a reply that the upstream sends to the first such query only
		once map[string]*dns.Msg

		noReply   *dns.Msg // The upstream fails the query (see repliedChain)
		servfail  = &dns.Msg{Rcode: dns.RcodeServerFailure}
		refusal   = &dns.Msg{Rcode: dns.RcodeRefused}
		nameError = &dns.Msg{Rcode: dns.RcodeNameError}
		truncated = &dns.Msg{Truncated: true}
		noAnswer  = &dns.Msg{} // No DNSKEY RRset; for a DS query no DS RRset, and no denial of it
		secure    = HaveField("Result", ValidationResultSecure)
	)

	// asked returns how often the upstream was asked query since c.queries was emptied
	asked := func(query string) int {
		n := 0

		for _, q := range c.queries {
			if q == query {
				n++
			}
		}

		return n
	}
	// refused returns the verdict for a reply that is Bogus, with what a client is told of it
	refused := func(ede uint16, text string) Verdict {
		return Verdict{Result: ValidationResultBogus, EDE: ede, Text: text}
	}
	// unanswered returns the verdict for a reply that is Bogus because a lookup got no reply
	unanswered := func(text string) Verdict {
		return Verdict{Result: ValidationResultBogus, EDE: noReachableAuthority, Text: text, NoReply: true}
	}

	BeforeEach(func(specCtx SpecContext) {
		ctx = specCtx
		c = newRepliedChain()
		once = map[string]*dns.Msg{}
		upstream = &mockResolver{ResolveFn: func(ctx context.Context, req *model.Request) (*model.Response, error) {
			q := req.Req.Question[0]
			query := dns.TypeToString[q.Qtype] + " " + q.Name

			if reply, first := once[query]; first {
				delete(once, query)

				c.queries = append(c.queries, query)

				return &model.Response{Res: reply}, nil
			}

			return c.resolve(ctx, req)
		}}

		logger, _ := log.NewMockEntry()
		v = NewValidator(ctx, c.anchors, logger, upstream, 1, 10, 150, 30, 3600)

		question = dns.Question{Name: "www." + c.child, Qtype: dns.TypeA, Qclass: dns.ClassINET}
		signed = signedA(question.Name, "192.0.2.1", c.childKey, c.childPriv, c.child)
		unsigned = &dns.Msg{Answer: signed.Answer[:1]}

		// www.signed.example. is no zone cut, which the walk for data without RRSIG asks about
		c.replies["DS "+question.Name] = &dns.Msg{Ns: c.childNSEC(question.Name, dns.TypeA)}
	})

	DescribeTable("is Bogus below a trust anchor with the extended error of the lookup, and nothing is kept of it",
		func(query string, reply *dns.Msg, ede uint16, text string, tries int) {
			c.replies[query] = reply

			// The verdict says of a lookup without reply, and of no other, that it got none
			verdict := refused(ede, text)
			if reply == noReply {
				verdict = unanswered(text)
			}

			// With its RRSIG and without: what the answer holds decides nothing
			for _, answer := range []*dns.Msg{signed, unsigned} {
				c.queries = nil

				Expect(v.Validate(ctx, answer, question)).Should(Equal(verdict))
				Expect(asked(query)).Should(Equal(tries))
			}

			// Issue #2120: the next validation looks up again, and finds the zone as it is
			delete(c.replies, query)

			Expect(v.Validate(ctx, signed, question)).Should(secure)
		},
		Entry("no reply to the DNSKEY query for the trust anchor, which is not asked again",
			"DNSKEY example.", noReply, noReachableAuthority, "no reply to the DNSKEY query for example.", 1),
		Entry("a server failure for the DNSKEY RRset of the trust anchor, twice",
			"DNSKEY example.", servfail, dnskeyMissing, "SERVFAIL reply to the DNSKEY query for example.", 2),
		Entry("a truncated reply for the DNSKEY RRset of the trust anchor, twice",
			"DNSKEY example.", truncated, networkError, "truncated reply to the DNSKEY query for example.", 2),
		Entry("a reply without the DNSKEY RRset of the trust anchor, twice",
			"DNSKEY example.", noAnswer, dnskeyMissing,
			"no records of the DNSKEY RRset in the reply to the DNSKEY query for example.", 2),
		Entry("no reply to the DS query for the zone, which is not asked again",
			"DS signed.example.", noReply, noReachableAuthority, "no reply to the DS query for signed.example.", 1),
		Entry("a server failure for the DS RRset of the zone, twice",
			"DS signed.example.", servfail, networkError, "SERVFAIL reply to the DS query for signed.example.", 2),
		Entry("a refusal for the DS RRset of the zone, twice",
			"DS signed.example.", refusal, networkError, "REFUSED reply to the DS query for signed.example.", 2),
		Entry("a truncated reply for the DS RRset of the zone, twice",
			"DS signed.example.", truncated, networkError, "truncated reply to the DS query for signed.example.", 2),
		Entry("a DS reply without the DS RRset of the zone and without its denial, twice",
			"DS signed.example.", noAnswer, nsecMissing,
			"neither the DS RRset nor its denial in the reply to the DS query for signed.example.", 2),
		Entry("a name error for the DS RRset of the zone without its denial, twice",
			"DS signed.example.", nameError, nsecMissing,
			"neither the DS RRset nor its denial in the reply to the DS query for signed.example.", 2),
		Entry("no reply to the DNSKEY query for the zone, which is not asked again",
			"DNSKEY signed.example.", noReply, noReachableAuthority,
			"no reply to the DNSKEY query for signed.example.", 1),
		Entry("a server failure for the DNSKEY RRset of the zone, twice",
			"DNSKEY signed.example.", servfail, dnskeyMissing, "SERVFAIL reply to the DNSKEY query for signed.example.", 2),
		Entry("a truncated reply for the DNSKEY RRset of the zone, twice",
			"DNSKEY signed.example.", truncated, networkError,
			"truncated reply to the DNSKEY query for signed.example.", 2),
		Entry("a reply without the DNSKEY RRset of the zone, twice",
			"DNSKEY signed.example.", noAnswer, dnskeyMissing,
			"no records of the DNSKEY RRset in the reply to the DNSKEY query for signed.example.", 2),
		Entry("a refusal for the DNSKEY RRset of the zone, twice",
			"DNSKEY signed.example.", refusal, dnskeyMissing, "REFUSED reply to the DNSKEY query for signed.example.", 2),
		Entry("a name error for the DNSKEY RRset of the zone, twice",
			"DNSKEY signed.example.", nameError, dnskeyMissing,
			"no records of the DNSKEY RRset in the reply to the DNSKEY query for signed.example.", 2),
	)

	DescribeTable("validates when the lookup is answered at its second try",
		func(query string, first *dns.Msg) {
			once[query] = first

			Expect(v.Validate(ctx, signed, question)).Should(secure)
			Expect(asked(query)).Should(Equal(2))
		},
		Entry("after a server failure for the DNSKEY RRset of the trust anchor", "DNSKEY example.", servfail),
		Entry("after a truncated reply for the DNSKEY RRset of the trust anchor", "DNSKEY example.", truncated),
		Entry("after a reply without the DNSKEY RRset of the trust anchor", "DNSKEY example.", noAnswer),
		Entry("after a server failure for the DS RRset of the zone", "DS signed.example.", servfail),
		Entry("after a truncated reply for the DS RRset of the zone", "DS signed.example.", truncated),
		Entry("after a DS reply without DS RRset and without its denial", "DS signed.example.", noAnswer),
		Entry("after a server failure for the DNSKEY RRset of the zone", "DNSKEY signed.example.", servfail),
		Entry("after a truncated reply for the DNSKEY RRset of the zone", "DNSKEY signed.example.", truncated),
		Entry("after a reply without the DNSKEY RRset of the zone", "DNSKEY signed.example.", noAnswer),
		Entry("after a name error for the DNSKEY RRset of the zone", "DNSKEY signed.example.", nameError),
	)

	It("takes the second try from the upstream queries of the validation", func() {
		// The chain of trust takes three queries. With a second try for the DS RRset, a validation
		// that may make three has none left for the DNSKEY RRset of the zone.
		logger, _ := log.NewMockEntry()

		once["DS "+c.child] = servfail
		v = NewValidator(ctx, c.anchors, logger, upstream, 1, 10, 150, 3, 3600)

		Expect(v.Validate(ctx, signed, question)).Should(Equal(Verdict{
			Result: ValidationResultBogus, EDE: dns.ExtendedErrorCodeDNSBogus,
			Text: "no upstream query left for the DNSKEY query for signed.example.", RanOut: true,
		}))
		Expect(c.queries).Should(Equal([]string{"DNSKEY example.", "DS signed.example.", "DS signed.example."}))

		once["DS "+c.child] = servfail
		v = NewValidator(ctx, c.anchors, logger, upstream, 1, 10, 150, 4, 3600)

		Expect(v.Validate(ctx, signed, question)).Should(secure)
	})

	It("makes a lookup that could not be completed once for a validation, whatever needs it", func() {
		// The answer has the RRSIGs of two signers, signed.example. and a zone below it. The walk
		// to either needs the DS RRset of signed.example.: the second walk asks no more for it.
		c.replies["DS "+c.child] = servfail
		question.Name = "www.sub." + c.child
		answer := signedA(question.Name, "192.0.2.1", c.childKey, c.childPriv, "sub."+c.child)
		answer.Answer = append(answer.Answer,
			signRRset(answer.Answer[:1], dns.TypeA, c.childKey, c.childPriv, c.child))

		Expect(v.Validate(ctx, answer, question)).Should(Equal(
			refused(networkError, "SERVFAIL reply to the DS query for signed.example.")))
		Expect(c.queries).Should(Equal([]string{"DNSKEY example.", "DS signed.example.", "DS signed.example."}))
	})

	It("is Indeterminate without a trust anchor above the name, for which no lookup is made", func() {
		// RFC 4033 §5: no trust anchor says whether signed.other. is signed
		key, priv, _ := newSignedZoneKey("signed.other.")
		question.Name = "www.signed.other."
		answer := signedA(question.Name, "192.0.2.1", key, priv, "signed.other.")

		Expect(v.Validate(ctx, answer, question)).Should(Equal(Verdict{Result: ValidationResultIndeterminate}))
		Expect(v.Validate(ctx, &dns.Msg{Answer: answer.Answer[:1]}, question)).
			Should(Equal(Verdict{Result: ValidationResultIndeterminate}))
		Expect(c.queries).Should(BeEmpty())
	})

	It("takes no NSEC record that is not Secure for the proof of an answer below a trust anchor", func() {
		// www.signed.example. has no TXT RRset, which only NSEC or NSEC3 records of signed.example.
		// prove (RFC 4035 §5.4). The NSEC record of a zone without trust anchor above it is
		// Indeterminate, and that of a zone whose DS lookup cannot be completed is not validated:
		// neither leaves the answer anything but unproven.
		question.Qtype = dns.TypeTXT

		key, priv, _ := newSignedZoneKey("other.")
		noData := &dns.Msg{Ns: signedNSEC("www.other.", key, priv, "other.", dns.TypeA)}

		Expect(v.Validate(ctx, noData, question)).Should(Equal(
			refused(dns.ExtendedErrorCodeDNSBogus, "no proof that www.signed.example. has no TXT RRset")))

		key, priv, _ = newSignedZoneKey("other.example.")
		noData = &dns.Msg{Ns: signedNSEC("www.other.example.", key, priv, "other.example.", dns.TypeA)}

		Expect(v.Validate(ctx, noData, question)).Should(Equal(refused(nsecMissing,
			"neither the DS RRset nor its denial in the reply to the DS query for other.example.")))
	})

	It("says that RRSIGs are missing for data without RRSIG that a signed zone holds", func() {
		Expect(v.Validate(ctx, unsigned, question)).Should(Equal(
			refused(dns.ExtendedErrorCodeRRSIGsMissing, "no RRSIG for www.signed.example. A in a signed zone")))
	})

	It("keeps a zone Bogus whose DNSKEY RRset came and does not verify, and does not ask again for it", func() {
		// The lookup is completed: the reply holds the DNSKEY RRset of the zone, here one that no
		// key which the DS RRset names has signed. Like every zone that is Bogus, this one stays so
		// for a minute.
		other, otherPriv, _ := newSignedZoneKey(c.child)
		bad := refused(dns.ExtendedErrorCodeDNSBogus, "the chain of trust to signed.example. is bogus")
		c.replies["DNSKEY "+c.child] = &dns.Msg{Answer: []dns.RR{
			other, signRRset([]dns.RR{other}, dns.TypeDNSKEY, other, otherPriv, c.child),
		}}

		Expect(v.Validate(ctx, signed, question)).Should(Equal(bad))
		Expect(asked("DNSKEY " + c.child)).Should(Equal(1))

		delete(c.replies, "DNSKEY "+c.child)

		c.queries = nil

		Expect(v.Validate(ctx, signed, question)).Should(Equal(bad))
		Expect(c.queries).Should(BeEmpty())
	})

	// A reply that fails validation is asked for once more, and so are the replies to the lookups
	// of its validation: the validation of a first reply stores no Bogus zone status, and that of
	// the second reply walks again (see FirstAsk and Again). The two have one budget.
	It("leaves a zone that the validation of a first reply found Bogus to that of the second", func() {
		// The DNSKEY reply for the zone comes without its RRSIG once: the lookup is completed, and
		// the zone is Bogus. The validation of the second reply finds the zone as it is, and so
		// does every validation after it.
		bogus := HaveField("Result", ValidationResultBogus)
		once["DNSKEY "+c.child] = &dns.Msg{Answer: []dns.RR{c.childKey}}
		first := FirstAsk(ctx)

		Expect(v.Validate(first, signed, question)).Should(bogus)

		c.queries = nil

		Expect(v.Validate(Again(first), signed, question)).Should(secure)
		Expect(c.queries).Should(Equal([]string{"DS signed.example.", "DNSKEY signed.example."}))

		c.queries = nil

		Expect(v.Validate(ctx, signed, question)).Should(secure)
		Expect(c.queries).Should(BeEmpty())
	})

	It("keeps a zone Bogus that the validation of a second reply found so", func() {
		// The DNSKEY RRset of the zone does not verify, whenever it is asked for. The validation of
		// the second reply asks for it once more, and what it finds holds for the next one.
		other, otherPriv, _ := newSignedZoneKey(c.child)
		bad := refused(dns.ExtendedErrorCodeDNSBogus, "the chain of trust to signed.example. is bogus")
		c.replies["DNSKEY "+c.child] = &dns.Msg{Answer: []dns.RR{
			other, signRRset([]dns.RR{other}, dns.TypeDNSKEY, other, otherPriv, c.child),
		}}
		first := FirstAsk(ctx)

		Expect(v.Validate(first, signed, question)).Should(Equal(bad))

		c.queries = nil

		Expect(v.Validate(Again(first), signed, question)).Should(Equal(bad))
		Expect(asked("DNSKEY " + c.child)).Should(Equal(1))

		c.queries = nil

		Expect(v.Validate(FirstAsk(ctx), signed, question)).Should(Equal(bad))
		Expect(v.Validate(ctx, signed, question)).Should(Equal(bad))
		Expect(c.queries).Should(BeEmpty())
	})

	It("validates the second reply with what the validation of the first left of its budget", func() {
		// The DNSKEY reply for the zone comes without its RRSIG once. The first validation makes
		// three upstream queries, and the second two more, for the zone that the first found Bogus:
		// a validator that may make four has none left for the last of them.
		logger, _ := log.NewMockEntry()
		noKeys := &dns.Msg{Answer: []dns.RR{c.childKey}}

		once["DNSKEY "+c.child] = noKeys
		v = NewValidator(ctx, c.anchors, logger, upstream, 1, 10, 150, 4, 3600)
		first := FirstAsk(ctx)

		_, spent := v.validate(first, signed, question)
		verifications := spent.verifications.Load()

		Expect(v.Validate(Again(first), signed, question)).Should(Equal(Verdict{
			Result: ValidationResultBogus, EDE: dns.ExtendedErrorCodeDNSBogus,
			Text: "no upstream query left for the DNSKEY query for signed.example.", RanOut: true,
		}))
		Expect(c.queries).Should(HaveLen(4))
		Expect(spent.verifications.Load()).Should(BeNumerically(">", verifications), "one count for both")

		// With five queries the second validation completes, and a validation by itself has its own
		once["DNSKEY "+c.child] = noKeys
		v = NewValidator(ctx, c.anchors, logger, upstream, 1, 10, 150, 5, 3600)
		first = FirstAsk(ctx)

		Expect(v.Validate(first, signed, question)).Should(HaveField("Result", ValidationResultBogus))
		Expect(v.Validate(Again(first), signed, question)).Should(secure)

		once["DNSKEY "+c.child] = noKeys
		v = NewValidator(ctx, c.anchors, logger, upstream, 1, 10, 150, 3, 3600)

		Expect(v.Validate(ctx, signed, question)).Should(HaveField("Result", ValidationResultBogus))
		Expect(v.Validate(ctx, signed, question)).Should(HaveField("Result", ValidationResultBogus),
			"the zone is Bogus in the cache")
	})

	It("says DNSSEC Bogus for an RRset that no RRSIG verifies", func() {
		forged, _ := signed.Answer[0].(*dns.A)
		forged.A = net.ParseIP("203.0.113.66")

		Expect(v.Validate(ctx, signed, question)).Should(Equal(
			refused(dns.ExtendedErrorCodeDNSBogus, "www.signed.example. A failed validation")))
	})

	// The shape of issue #2120: an answer that is a CNAME chain across several signed zones, with
	// a lookup for one of them in the middle that fails
	Describe("for one zone of a CNAME chain across several zones", func() {
		var answer *dns.Msg

		BeforeEach(func() {
			zones := []string{"a.example.", "b.example.", "c.example.", "d.example."}
			question.Name = "www." + zones[0]
			answer = new(dns.Msg)

			for i, zone := range zones {
				key, priv := c.delegate(c.parent, c.parentKey, c.parentPriv, zone)

				if i == len(zones)-1 {
					answer.Answer = append(answer.Answer, signedA("www."+zone, "192.0.2.1", key, priv, zone).Answer...)

					break
				}

				alias := &dns.CNAME{
					Hdr:    dns.RR_Header{Name: "www." + zone, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "www." + zones[i+1],
				}
				answer.Answer = append(answer.Answer, alias, signRRset([]dns.RR{alias}, dns.TypeCNAME, key, priv, zone))
			}
		})

		It("validates when the lookup is answered at its second try", func() {
			once["DNSKEY c.example."] = servfail

			Expect(v.Validate(ctx, answer, question)).Should(secure)
			Expect(asked("DNSKEY c.example.")).Should(Equal(2))
		})

		It("refuses the one answer whose validation it stops, and validates the next", func() {
			proper := c.replies["DS c.example."]
			c.replies["DS c.example."] = noReply

			Expect(v.Validate(ctx, answer, question)).Should(Equal(unanswered("no reply to the DS query for c.example.")))

			c.replies["DS c.example."] = proper

			Expect(v.Validate(ctx, answer, question)).Should(secure)
		})
	})
})
