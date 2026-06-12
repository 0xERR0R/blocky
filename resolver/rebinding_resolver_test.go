package resolver

import (
	"context"
	"errors"
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

// rebindTestA builds an A RR with the given owner name and address.
func rebindTestA(name, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(ip),
	}
}

// rebindTestAAAA builds an AAAA RR with the given owner name and address.
func rebindTestAAAA(name, ip string) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
		AAAA: net.ParseIP(ip),
	}
}

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
			logger, hook := log.NewMockEntry()

			sut.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
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

		It("passes through HTTPS answers with public hints", func() {
			mockAnswer.Answer = []dns.RR{newHTTPSRecord()}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", HTTPS))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(HaveLen(1))
			Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
		})

		It("uses a fixed reason (no attacker-controlled IP in metrics labels)", func() {
			mockAnswer.Answer = []dns.RR{rebindTestA("rebind.example.com.", "192.168.1.100")}

			resp, err := sut.Resolve(ctx, newRequest("rebind.example.com.", A))
			Expect(err).Should(Succeed())
			Expect(resp.Reason).Should(Equal("FILTERED (rebinding protection)"))
		})

		It("passes through records without an address (nil IP)", func() {
			a := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}}
			mockAnswer.Answer = []dns.RR{a}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", A))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(ConsistOf(a))
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

		It("filters CNAME chains ending in a private IP", func() {
			cname := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: "evil.example.org.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "target.example.org.",
			}
			mockAnswer.Answer = []dns.RR{cname, rebindTestA("target.example.org.", "10.0.0.5")}

			Expect(sut.Resolve(ctx, newRequest("evil.example.org.", A))).
				Should(HaveResponseType(ResponseTypeFILTERED))
		})

		It("passes through public IPv4 answers", func() {
			a := rebindTestA("example.com.", "1.2.3.4")
			mockAnswer.Answer = []dns.RR{a}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", A))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(ConsistOf(a))
		})

		It("passes through public IPv6 answers", func() {
			aaaa := rebindTestAAAA("example.com.", "2001:db8::1")
			mockAnswer.Answer = []dns.RR{aaaa}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", AAAA))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(ConsistOf(aaaa))
		})

		It("passes through answers without address records", func() {
			txt := &dns.TXT{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{"hello"},
			}
			mockAnswer.Answer = []dns.RR{txt}

			resp, err := sut.Resolve(ctx, newRequest("example.com.", TXT))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(ConsistOf(txt))
		})

		It("passes through empty responses", func() {
			resp, err := sut.Resolve(ctx, newRequest("example.com.", A))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Answer).Should(BeEmpty())
			Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
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

	When("chained below a validating DNSSEC resolver", func() {
		It("passes the synthetic filtered response through validation as insecure", func() {
			// DNSSECResolver sits above this resolver in the server chain; the
			// synthetic empty response carries no RRSIGs and must be treated as
			// insecure/unsigned, not bogus (spec: "DNSSEC interplay")
			mockAnswer.Answer = []dns.RR{rebindTestA("rebind.example.com.", "192.168.1.100")}

			dnssecRes, err := NewDNSSECResolver(ctx, config.DNSSEC{Validate: true}, m)
			Expect(err).Should(Succeed())

			chained := Chain(dnssecRes, sut, m)

			resp, err := chained.Resolve(ctx, newRequest("rebind.example.com.", A))
			Expect(err).Should(Succeed())
			Expect(resp).Should(SatisfyAll(
				HaveNoAnswer(),
				HaveResponseType(ResponseTypeFILTERED),
				HaveReturnCode(dns.RcodeSuccess),
			))
			// the validator must classify the unsigned synthetic response as insecure
			// without issuing any DNSKEY/DS lookups — one upstream call only
			Expect(m.Calls).Should(HaveLen(1))
			Expect(resp.Res.AuthenticatedData).Should(BeFalse())
		})
	})
})
