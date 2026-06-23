package resolver

import (
	"context"
	"errors"
	"net"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

// rebindTestA builds an A RR with the given owner name and address. It panics on
// invalid literals: a nil IP would silently pass through the resolver (nil is
// never blocked by design), turning a typo'd spec into a vacuous pass.
func rebindTestA(name, ip string) *dns.A {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		panic("rebindTestA: invalid IP literal " + ip)
	}

	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   parsed,
	}
}

// rebindTestAAAA builds an AAAA RR with the given owner name and address.
// See rebindTestA for why it panics on invalid literals.
func rebindTestAAAA(name, ip string) *dns.AAAA {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		panic("rebindTestAAAA: invalid IP literal " + ip)
	}

	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
		AAAA: parsed,
	}
}

// unrelatedDNSSECAnchor is a syntactically valid KSK trust anchor for a zone that does
// not cover the rebinding test names, so unsigned answers are classified Indeterminate.
const unrelatedDNSSECAnchor = "dnssec-test-anchor. 172800 IN DNSKEY 257 3 8 " +
	"AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8k" +
	"vArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr" +
	"+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6" +
	"UwNR1AkUTV74bU="

var _ = Describe("RebindingProtectionResolver", func() {
	var (
		sut        *RebindingProtectionResolver
		sutConfig  config.RebindingProtection
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

		sutConfig = config.RebindingProtection{Enable: true}
		mockAnswer = new(dns.Msg)
	})

	JustBeforeEach(func() {
		sut = NewRebindingProtectionResolver(sutConfig)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)
		sut.Next(m)
	})

	Describe("IsEnabled", func() {
		It("is true when enabled", func() {
			Expect(sut.IsEnabled()).Should(BeTrue())
		})
	})

	Describe("LogConfig", func() {
		It("should log something", func() {
			lgr, rec := log.NewRecorder()

			sut.LogConfig(lgr)

			Expect(rec.Records()).ShouldNot(BeEmpty())
		})
	})

	When("protection is disabled", func() {
		BeforeEach(func() {
			sutConfig = config.RebindingProtection{}
		})

		It("passes private answers through", func() {
			a := rebindTestA("rebind.example.com.", "192.168.1.100")
			mockAnswer.Answer = []dns.RR{a}

			resp, err := sut.Resolve(ctx, newRequest("rebind.example.com.", A))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(ConsistOf(a))

			// delegated to next resolver
			Expect(m.Calls).Should(HaveLen(1))
		})
	})

	When("the answer does not come from the general upstreams", func() {
		// the resolver sits above blocking and the cache; answers produced by
		// trusted local sources are recognized by response type and never filtered
		DescribeTable("passes private answers through untouched",
			func(rType ResponseType) {
				m = &mockResolver{}
				m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer, RType: rType}, nil)
				sut.Next(m)

				a := rebindTestA("router.home.lab.", "192.168.2.1")
				mockAnswer.Answer = []dns.RR{a}

				resp, err := sut.Resolve(ctx, newRequest("router.home.lab.", A))
				Expect(err).Should(Succeed())
				Expect(resp.RType).Should(Equal(rType))
				Expect(resp.Res.Answer).Should(ConsistOf(a))
			},
			Entry("blocked", ResponseTypeBLOCKED),
			Entry("conditional", ResponseTypeCONDITIONAL),
			Entry("custom DNS", ResponseTypeCUSTOMDNS),
			Entry("hosts file", ResponseTypeHOSTSFILE),
			Entry("special-use domain", ResponseTypeSPECIAL),
		)

		It("still filters cached upstream answers (incl. redis-synced entries)", func() {
			m = &mockResolver{}
			m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer, RType: ResponseTypeCACHED, Reason: "CACHED"}, nil)
			sut.Next(m)

			mockAnswer.Answer = []dns.RR{rebindTestA("rebind.example.com.", "192.168.1.100")}

			Expect(sut.Resolve(ctx, newRequest("rebind.example.com.", A))).
				Should(SatisfyAll(
					HaveNoAnswer(),
					HaveResponseType(ResponseTypeFILTERED),
				))
		})
	})

	When("protection is enabled", func() {
		DescribeTable("filters answers containing non-public IPs",
			func(rr dns.RR) {
				mockAnswer.Answer = []dns.RR{rr}

				Expect(sut.Resolve(ctx, newRequest("rebind.example.com.", A))).
					Should(SatisfyAll(
						HaveNoAnswer(),
						HaveResponseType(ResponseTypeFILTERED),
						HaveReturnCode(dns.RcodeSuccess),
					))
			},
			Entry("RFC1918 10/8", rebindTestA("rebind.example.com.", "10.1.2.3")),
			Entry("RFC1918 172.16/12", rebindTestA("rebind.example.com.", "172.16.5.5")),
			Entry("RFC1918 192.168/16", rebindTestA("rebind.example.com.", "192.168.1.100")),
			Entry("IPv4 loopback", rebindTestA("rebind.example.com.", "127.0.0.1")),
			Entry("IPv4 link-local", rebindTestA("rebind.example.com.", "169.254.10.10")),
			Entry("IPv4 unspecified", rebindTestA("rebind.example.com.", "0.0.0.0")),
			Entry("IPv6 ULA", rebindTestAAAA("rebind.example.com.", "fd00::1")),
			Entry("IPv6 loopback", rebindTestAAAA("rebind.example.com.", "::1")),
			Entry("IPv6 link-local", rebindTestAAAA("rebind.example.com.", "fe80::1")),
			Entry("IPv6 unspecified", rebindTestAAAA("rebind.example.com.", "::")),
			Entry("IPv4-mapped IPv6 private", rebindTestAAAA("rebind.example.com.", "::ffff:192.168.1.1")),
		)

		It("filters HTTPS answers with a private ipv4hint", func() {
			https := &dns.HTTPS{SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: "rebind.example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("192.168.1.100")}},
				},
			}}
			mockAnswer.Answer = []dns.RR{https}

			Expect(sut.Resolve(ctx, newRequest("rebind.example.com.", HTTPS))).
				Should(SatisfyAll(
					HaveNoAnswer(),
					HaveResponseType(ResponseTypeFILTERED),
				))
		})

		It("filters SVCB answers with a ULA ipv6hint", func() {
			svcb := &dns.SVCB{
				Hdr:      dns.RR_Header{Name: "rebind.example.com.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("fd00::1")}},
				},
			}
			mockAnswer.Answer = []dns.RR{svcb}

			Expect(sut.Resolve(ctx, newRequest("rebind.example.com.", dns.Type(dns.TypeSVCB)))).
				Should(SatisfyAll(
					HaveNoAnswer(),
					HaveResponseType(ResponseTypeFILTERED),
				))
		})

		It("filters HTTPS answers where only a later hint is private", func() {
			https := &dns.HTTPS{SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: "rebind.example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("192.168.1.100")}},
					&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("fd00::1")}},
				},
			}}
			mockAnswer.Answer = []dns.RR{https}

			Expect(sut.Resolve(ctx, newRequest("rebind.example.com.", HTTPS))).
				Should(SatisfyAll(
					HaveNoAnswer(),
					HaveResponseType(ResponseTypeFILTERED),
				))
		})

		DescribeTable("passes through answers without non-public IPs",
			func(qType dns.Type, rrs ...dns.RR) {
				mockAnswer.Answer = rrs

				resp, err := sut.Resolve(ctx, newRequest("example.com.", qType))
				Expect(err).Should(Succeed())
				Expect(resp.Res.Answer).Should(ConsistOf(rrs))
				Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
			},
			Entry("public IPv4", A, rebindTestA("example.com.", "1.2.3.4")),
			Entry("public IPv6", AAAA, rebindTestAAAA("example.com.", "2001:db8::1")),
			Entry("HTTPS with public hints", HTTPS, newHTTPSRecord()),
			Entry("record without an address (nil IP)", A,
				&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}}),
			Entry("answer without address records", TXT, &dns.TXT{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{"hello"},
			}),
			Entry("empty response", A),
		)

		It("uses a fixed reason (no attacker-controlled IP in metrics labels)", func() {
			mockAnswer.Answer = []dns.RR{rebindTestA("rebind.example.com.", "192.168.1.100")}

			resp, err := sut.Resolve(ctx, newRequest("rebind.example.com.", A))
			Expect(err).Should(Succeed())
			Expect(resp.Reason).Should(Equal("FILTERED (rebinding protection)"))
		})

		It("filters answers mixing public and private records", func() {
			mockAnswer.Answer = []dns.RR{
				rebindTestA("rebind.example.com.", "1.2.3.4"),
				rebindTestA("rebind.example.com.", "192.168.1.100"),
			}

			Expect(sut.Resolve(ctx, newRequest("rebind.example.com.", A))).
				Should(SatisfyAll(
					HaveNoAnswer(),
					HaveResponseType(ResponseTypeFILTERED),
				))
		})

		It("filters responses whose additional section carries a private IP", func() {
			// per RFC 9460 §5 an upstream may attach the HTTPS/SVCB TargetName's
			// address records in the additional section; they must be inspected
			// like answer records
			https := &dns.HTTPS{SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: "rebind.example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   "target.example.com.",
			}}
			mockAnswer.Answer = []dns.RR{https}
			mockAnswer.Extra = []dns.RR{rebindTestA("target.example.com.", "192.168.1.1")}

			Expect(sut.Resolve(ctx, newRequest("rebind.example.com.", HTTPS))).
				Should(SatisfyAll(
					HaveNoAnswer(),
					HaveResponseType(ResponseTypeFILTERED),
				))
		})

		It("filters responses whose authority section carries a private IP", func() {
			mockAnswer.Ns = []dns.RR{rebindTestA("rebind.example.com.", "192.168.1.1")}

			Expect(sut.Resolve(ctx, newRequest("rebind.example.com.", A))).
				Should(HaveResponseType(ResponseTypeFILTERED))
		})

		It("filters private answers for requests without a question section", func() {
			req := newRequest("rebind.example.com.", A)
			req.Req.Question = nil
			mockAnswer.Answer = []dns.RR{rebindTestA("rebind.example.com.", "192.168.1.100")}

			Expect(sut.Resolve(ctx, req)).Should(HaveResponseType(ResponseTypeFILTERED))
		})

		It("obfuscates the dropped IP in the debug log when log privacy is enabled", func() {
			// CaptureGlobal must precede resolver construction: PrefixedLog captures
			// slog.Default() at construction time, so the recorder is only wired in
			// if the global is swapped first.
			rec, restore := log.CaptureGlobal()
			DeferCleanup(restore)

			localSut := NewRebindingProtectionResolver(sutConfig)
			localM := &mockResolver{}
			localM.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)
			localSut.Next(localM)

			util.LogPrivacy.Store(true)
			DeferCleanup(func() { util.LogPrivacy.Store(false) })

			mockAnswer.Answer = []dns.RR{rebindTestA("rebind.example.com.", "192.168.1.100")}

			_, err := localSut.Resolve(ctx, newRequest("rebind.example.com.", A))
			Expect(err).Should(Succeed())

			// the IP is answer content; like the domain, it must not appear
			// in clear text when log privacy is on
			Expect(rec.Messages()).Should(ContainElement(ContainSubstring("dropped answer")))
			Expect(rec.Messages()).ShouldNot(ContainElement(ContainSubstring("192.168.1.100")))
		})

		It("filters CNAME chains ending in a private IP", func() {
			cname := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: "evil.example.org.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "target.example.org.",
			}
			mockAnswer.Answer = []dns.RR{cname, rebindTestA("target.example.org.", "10.0.0.5")}

			Expect(sut.Resolve(ctx, newRequest("evil.example.org.", A))).
				Should(HaveResponseType(ResponseTypeFILTERED))
		})
	})

	When("a domain is allowlisted", func() {
		BeforeEach(func() {
			sutConfig = config.RebindingProtection{
				Enable: true,
				// mixed case + trailing dot: exercises normalization
				AllowedDomains: []string{"Intranet.Example.COM."},
			}
		})

		It("passes through private answers for the exact domain", func() {
			a := rebindTestA("intranet.example.com.", "192.168.1.50")
			mockAnswer.Answer = []dns.RR{a}

			resp, err := sut.Resolve(ctx, newRequest("intranet.example.com.", A))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(ConsistOf(a))
		})

		It("passes through private answers for subdomains", func() {
			a := rebindTestA("nas.intranet.example.com.", "192.168.1.51")
			mockAnswer.Answer = []dns.RR{a}

			resp, err := sut.Resolve(ctx, newRequest("nas.intranet.example.com.", A))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(ConsistOf(a))
		})

		It("still filters sibling domains", func() {
			mockAnswer.Answer = []dns.RR{rebindTestA("notintranet.example.com.", "192.168.1.52")}

			Expect(sut.Resolve(ctx, newRequest("notintranet.example.com.", A))).
				Should(HaveResponseType(ResponseTypeFILTERED))
		})

		It("still filters CNAMEs pointing at an allowlisted name", func() {
			// the question name decides; an attacker CNAME-ing to an allowlisted
			// name must not bypass protection
			cname := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: "evil.example.org.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "intranet.example.com.",
			}
			mockAnswer.Answer = []dns.RR{cname, rebindTestA("intranet.example.com.", "192.168.1.50")}

			Expect(sut.Resolve(ctx, newRequest("evil.example.org.", A))).
				Should(HaveResponseType(ResponseTypeFILTERED))
		})

		It("does not treat escaped dots as label boundaries", func() {
			// `evil\.intranet` is a single label directly under example.com —
			// NOT a subdomain of the allowlisted intranet.example.com
			mockAnswer.Answer = []dns.RR{rebindTestA(`evil\.intranet.example.com.`, "192.168.1.66")}

			Expect(sut.Resolve(ctx, newRequest(`evil\.intranet.example.com.`, A))).
				Should(HaveResponseType(ResponseTypeFILTERED))
		})

		It("never applies the allowlist to multi-question requests", func() {
			// with more than one question the answers cannot be attributed to a
			// single name, so the allowlist must not exempt them (fail closed)
			req := newRequest("intranet.example.com.", A)
			req.Req.Question = append(req.Req.Question,
				dns.Question{Name: "evil.example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
			mockAnswer.Answer = []dns.RR{rebindTestA("intranet.example.com.", "192.168.1.50")}

			Expect(sut.Resolve(ctx, req)).Should(HaveResponseType(ResponseTypeFILTERED))
		})
	})

	When("a single-label domain is allowlisted", func() {
		BeforeEach(func() {
			sutConfig = config.RebindingProtection{
				Enable:         true,
				AllowedDomains: []string{"lan"},
			}
		})

		It("passes through private answers for names under it", func() {
			a := rebindTestA("router.lan.", "192.168.2.1")
			mockAnswer.Answer = []dns.RR{a}

			resp, err := sut.Resolve(ctx, newRequest("router.lan.", A))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(ConsistOf(a))
		})
	})

	When("the next resolver returns an error", func() {
		JustBeforeEach(func() {
			m = &mockResolver{}
			m.On("Resolve", mock.Anything).Return(nil, errors.New("upstream error"))
			sut.Next(m)
		})

		It("propagates the error", func() {
			_, err := sut.Resolve(ctx, newRequest("example.com.", A))
			Expect(err).Should(MatchError("upstream error"))
		})
	})

	When("chained above a validating DNSSEC resolver", func() {
		It("filters the answer after DNSSEC validation, with no AD flag", func() {
			// the validator sits below this resolver in the server chain and sees the real
			// upstream answer; the synthetic filtered response replaces it after validation
			// and carries no AD flag (spec: "DNSSEC interplay")
			mockAnswer.Answer = []dns.RR{rebindTestA("rebind.example.com.", "192.168.1.100")}

			// Use a trust anchor that does NOT cover rebind.example.com so the unsigned
			// answer is classified Indeterminate (passed through) rather than failing closed,
			// letting the rebinding resolver above filter it.
			dnssecRes, err := NewDNSSECResolver(ctx, config.DNSSEC{
				Validate:     true,
				TrustAnchors: []string{unrelatedDNSSECAnchor},
			}, m)
			Expect(err).Should(Succeed())

			chained := Chain(sut, dnssecRes, m)

			resp, err := chained.Resolve(ctx, newRequest("rebind.example.com.", A))
			Expect(err).Should(Succeed())
			Expect(resp).Should(SatisfyAll(
				HaveNoAnswer(),
				HaveResponseType(ResponseTypeFILTERED),
				HaveReturnCode(dns.RcodeSuccess),
			))
			Expect(resp.Res.AuthenticatedData).Should(BeFalse())
		})
	})

	When("chained above a caching resolver", func() {
		It("re-inspects cached answers on every hit", func() {
			mockAnswer.Answer = []dns.RR{rebindTestA("rebind.example.com.", "192.168.1.100")}

			cachingCfg, err := config.WithDefaults[config.Caching]()
			Expect(err).Should(Succeed())

			cachingRes, err := NewCachingResolver(ctx, cachingCfg, nil)
			Expect(err).Should(Succeed())

			chained := Chain(sut, cachingRes, m)

			By("first query is resolved upstream and filtered", func() {
				resp, err := chained.Resolve(ctx, newRequest("rebind.example.com.", A))
				Expect(err).Should(Succeed())
				Expect(resp).Should(SatisfyAll(
					HaveNoAnswer(),
					HaveResponseType(ResponseTypeFILTERED),
					HaveReturnCode(dns.RcodeSuccess),
				))
				Expect(m.Calls).Should(HaveLen(1))
			})

			By("second query hits the cache and is filtered again", func() {
				resp, err := chained.Resolve(ctx, newRequest("rebind.example.com.", A))
				Expect(err).Should(Succeed())
				Expect(resp).Should(SatisfyAll(
					HaveNoAnswer(),
					HaveResponseType(ResponseTypeFILTERED),
					HaveReturnCode(dns.RcodeSuccess),
				))
				// the real answer is cached below this resolver and re-filtered
				// on every hit; the upstream was not asked again
				Expect(m.Calls).Should(HaveLen(1))
			})
		})

		It("never filters conditional answers, also on repeat queries", func() {
			// regression: the cache used to store conditional answers and re-serve
			// them re-labeled as CACHED, so trusted internal-zone answers were
			// inspected and filtered from the second query onward
			a := rebindTestA("router.home.lab.", "192.168.2.1")
			mockAnswer.Answer = []dns.RR{a}

			m = &mockResolver{}
			m.On("Resolve", mock.Anything).
				Return(&Response{Res: mockAnswer, RType: ResponseTypeCONDITIONAL, Reason: "CONDITIONAL"}, nil)

			cachingCfg, err := config.WithDefaults[config.Caching]()
			Expect(err).Should(Succeed())

			cachingRes, err := NewCachingResolver(ctx, cachingCfg, nil)
			Expect(err).Should(Succeed())

			chained := Chain(sut, cachingRes, m)

			By("first query passes through", func() {
				resp, err := chained.Resolve(ctx, newRequest("router.home.lab.", A))
				Expect(err).Should(Succeed())
				Expect(resp.RType).Should(Equal(ResponseTypeCONDITIONAL))
				Expect(resp.Res.Answer).Should(ConsistOf(a))
			})

			By("repeat query passes through as well", func() {
				resp, err := chained.Resolve(ctx, newRequest("router.home.lab.", A))
				Expect(err).Should(Succeed())
				Expect(resp.RType).Should(Equal(ResponseTypeCONDITIONAL))
				Expect(resp.Res.Answer).Should(ConsistOf(a))

				// conditional answers are served fresh, never from the cache
				Expect(m.Calls).Should(HaveLen(2))
			})
		})
	})
})
