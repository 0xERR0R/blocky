package resolver

import (
	"context"
	"net"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

// svcbKeys returns the SvcParam keys present in the given SVCB/HTTPS value list.
func svcbKeys(values []dns.SVCBKeyValue) []dns.SVCBKey {
	keys := make([]dns.SVCBKey, 0, len(values))
	for _, v := range values {
		keys = append(keys, v.Key())
	}

	return keys
}

// newHTTPSRecord builds an HTTPS RR for example.com. carrying alpn, an ipv4hint and an ipv6hint.
func newHTTPSRecord() *dns.HTTPS {
	return &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
		Priority: 1,
		Target:   ".",
		Value: []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: []string{"h3", "h2"}},
			&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("104.16.123.96")}},
			&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2606:4700::6810:7b60")}},
		},
	}}
}

// newHTTPSRecordNoV6Hint builds an HTTPS RR for example.com. with alpn and an ipv4hint, but no ipv6hint.
func newHTTPSRecordNoV6Hint() *dns.HTTPS {
	return &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
		Priority: 1,
		Target:   ".",
		Value: []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: []string{"h3", "h2"}},
			&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("104.16.123.96")}},
		},
	}}
}

// newRRSIG builds a minimal RRSIG RR covering the given record type.
func newRRSIG(covered uint16) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: covered,
		SignerName:  "example.com.",
	}
}

// rrsigCoveredTypes returns the record types covered by the RRSIGs in the given answer set.
func rrsigCoveredTypes(answers []dns.RR) []uint16 {
	var covered []uint16

	for _, rr := range answers {
		if sig, ok := rr.(*dns.RRSIG); ok {
			covered = append(covered, sig.TypeCovered)
		}
	}

	return covered
}

var _ = Describe("FilteringResolver", func() {
	var (
		sut        *FilteringResolver
		sutConfig  config.Filtering
		m          *mockResolver
		mockAnswer *dns.Msg

		ctx      context.Context
		cancelFn context.CancelFunc
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		mockAnswer = new(dns.Msg)
	})

	JustBeforeEach(func() {
		sut = NewFilteringResolver(sutConfig)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)
		sut.Next(m)
	})

	Describe("IsEnabled", func() {
		It("is false", func() {
			Expect(sut.IsEnabled()).Should(BeFalse())
		})
	})

	Describe("LogConfig", func() {
		It("should log something", func() {
			logger, rec := log.NewRecorder()

			sut.LogConfig(logger)

			Expect(rec.Records()).ShouldNot(BeEmpty())
		})
	})

	When("Filtering query types are defined", func() {
		BeforeEach(func() {
			sutConfig = config.Filtering{
				QueryTypes: config.NewQTypeSet(AAAA, MX),
			}
		})
		It("Should delegate to next resolver if request query has other type", func() {
			Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			// delegated to next resolver
			Expect(m.Calls).Should(HaveLen(1))
		})
		It("Should return empty answer for defined query type", func() {
			Expect(sut.Resolve(ctx, newRequest("example.com.", AAAA))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeFILTERED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			// no call of next resolver
			Expect(m.Calls).Should(BeZero())
		})
	})

	When("No filtering query types are defined", func() {
		BeforeEach(func() {
			sutConfig = config.Filtering{}
		})
		It("Should return empty answer without error", func() {
			Expect(sut.Resolve(ctx, newRequest("example.com.", AAAA))).
				Should(
					SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dns.RcodeSuccess),
					))

			// delegated to next resolver
			Expect(m.Calls).Should(HaveLen(1))
		})
	})

	When("AAAA queries are filtered", func() {
		BeforeEach(func() {
			sutConfig = config.Filtering{
				QueryTypes: config.NewQTypeSet(AAAA),
			}
		})

		It("strips the ipv6hint from HTTPS answers while keeping other SvcParams", func() {
			mockAnswer.Answer = []dns.RR{newHTTPSRecord()}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", HTTPS))
			Expect(err).Should(Succeed())

			// upstream was queried and the response delegated through
			Expect(m.Calls).Should(HaveLen(1))
			Expect(resp.Res.Answer).Should(HaveLen(1))

			https, ok := resp.Res.Answer[0].(*dns.HTTPS)
			Expect(ok).Should(BeTrue())

			keys := svcbKeys(https.Value)
			Expect(keys).ShouldNot(ContainElement(dns.SVCB_IPV6HINT))
			Expect(keys).Should(ContainElements(dns.SVCB_ALPN, dns.SVCB_IPV4HINT))
		})

		It("strips the ipv6hint from SVCB answers", func() {
			svcb := &dns.SVCB{
				Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2606:4700::6810:7b60")}},
				},
			}
			mockAnswer.Answer = []dns.RR{svcb}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", dns.Type(dns.TypeSVCB)))
			Expect(err).Should(Succeed())

			result, ok := resp.Res.Answer[0].(*dns.SVCB)
			Expect(ok).Should(BeTrue())
			Expect(svcbKeys(result.Value)).ShouldNot(ContainElement(dns.SVCB_IPV6HINT))
		})

		It("leaves non-SVCB answers untouched", func() {
			a := &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("104.16.123.96"),
			}
			mockAnswer.Answer = []dns.RR{a}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", A))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(ConsistOf(a))
		})

		It("does not touch answers of non-HTTPS/SVCB queries", func() {
			// HTTPS/SVCB records only legitimately appear in the answer of HTTPS/SVCB queries,
			// so the answer of an A query is never scanned for hints
			mockAnswer.Answer = []dns.RR{newHTTPSRecord()}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", A))
			Expect(err).Should(Succeed())

			https, ok := resp.Res.Answer[0].(*dns.HTTPS)
			Expect(ok).Should(BeTrue())
			Expect(svcbKeys(https.Value)).Should(ContainElement(dns.SVCB_IPV6HINT))
		})

		It("clears the AD bit when an ipv6hint is removed", func() {
			mockAnswer.AuthenticatedData = true
			mockAnswer.Answer = []dns.RR{newHTTPSRecord()}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", HTTPS))
			Expect(err).Should(Succeed())
			Expect(resp.Res.AuthenticatedData).Should(BeFalse())
		})

		It("drops only RRSIGs covering the modified record type, keeping signatures of other types", func() {
			mockAnswer.Answer = []dns.RR{
				newHTTPSRecord(),
				newRRSIG(dns.TypeHTTPS),
				newRRSIG(dns.TypeSVCB),
				newRRSIG(dns.TypeCNAME),
			}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", HTTPS))
			Expect(err).Should(Succeed())

			// only the signature covering the modified HTTPS RRset is dropped; the SVCB and
			// CNAME signatures cover RRsets that were not modified and must be kept
			Expect(rrsigCoveredTypes(resp.Res.Answer)).Should(ConsistOf(dns.TypeSVCB, dns.TypeCNAME))
		})

		It("keeps the AD bit and signatures when there is no ipv6hint to remove", func() {
			mockAnswer.AuthenticatedData = true
			sig := newRRSIG(dns.TypeHTTPS)
			mockAnswer.Answer = []dns.RR{newHTTPSRecordNoV6Hint(), sig}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", HTTPS))
			Expect(err).Should(Succeed())

			Expect(resp.Res.AuthenticatedData).Should(BeTrue())
			Expect(resp.Res.Answer).Should(ContainElement(sig))
		})
	})

	When("AAAA queries are not filtered", func() {
		BeforeEach(func() {
			sutConfig = config.Filtering{
				QueryTypes: config.NewQTypeSet(MX),
			}
		})

		It("keeps the ipv6hint in HTTPS answers", func() {
			mockAnswer.Answer = []dns.RR{newHTTPSRecord()}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", HTTPS))
			Expect(err).Should(Succeed())

			https, ok := resp.Res.Answer[0].(*dns.HTTPS)
			Expect(ok).Should(BeTrue())
			Expect(svcbKeys(https.Value)).Should(ContainElement(dns.SVCB_IPV6HINT))
		})
	})
})
