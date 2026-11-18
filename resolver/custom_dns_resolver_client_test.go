package resolver

import (
	"context"
	"net"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/creasty/defaults"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("CustomDNSResolver clientMapping", func() {
	var (
		TTL = uint32(time.Now().Second() + 1)

		sut *CustomDNSResolver
		m   *mockResolver
		cfg config.CustomDNS

		ctx context.Context
	)

	a := func(ip string) dns.RR { return &dns.A{A: net.ParseIP(ip)} }
	aaaa := func(ip string) dns.RR { return &dns.AAAA{AAAA: net.ParseIP(ip)} }

	// the default client, outside every clientMapping entry
	const other = "10.1.1.1"

	BeforeEach(func() {
		var cancelFn context.CancelFunc

		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		cfg = config.CustomDNS{
			Mapping: config.CustomDNSMapping{
				"printer.lan": {a("192.168.178.3"), aaaa("2001:db8::3")},
				"ha.home.lan": {a("192.168.178.10")},
				"shared.lan":  {a("192.168.178.20")},
				"corp.lan":    {a("192.168.178.30")},
			},
			Zone: config.ZoneFileDNS{
				RRs: config.CustomDNSMapping{
					"alias.lan.":      {&dns.CNAME{Target: "www.domain.io", Hdr: dns.RR_Header{Ttl: TTL}}},
					"home-alias.lan.": {&dns.CNAME{Target: "x.home.lan", Hdr: dns.RR_Header{Ttl: TTL}}},
				},
			},
			ClientMapping: config.CustomDNSClientMapping{
				"192.168.68.0/22": {
					"www.domain.io": {a("192.168.1.75")},
					"home.lan":      {a("192.168.68.22")},
					"printer.lan":   {a("192.168.68.3")},
					"vpn.corp.lan":  {a("192.168.68.30")},
				},
				"192.168.68.0/24":     {"www.domain.io": {a("192.168.1.76")}},
				"192.168.68.5":        {"www.domain.io": {a("192.168.1.77")}},
				"Laptop, tablet":      {"www.domain.io": {a("10.0.0.1")}},
				"phone*":              {"www.domain.io": {a("10.0.0.2")}},
				"192.168.70.9":        {},
				"2001:db8:68::/64":    {"www.domain.io": {aaaa("2001:db8::75")}},
				"2001:DB8:68:0::abcd": {"www.domain.io": {aaaa("2001:db8::77")}},
			},
			CustomTTL:           config.Duration(time.Duration(TTL) * time.Second),
			FilterUnmappedTypes: true,
		}
	})

	JustBeforeEach(func() {
		sut = NewCustomDNSResolver(cfg)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	resolve := func(question string, qType dns.Type, ip string, names ...string) (*Response, error) {
		return sut.Resolve(ctx, newRequestWithClient(question, qType, ip, names...))
	}

	answeredWith := func(question string, qType dns.Type, answer string) OmegaMatcher {
		return SatisfyAll(
			BeDNSRecord(question, qType, answer),
			HaveTTL(BeNumerically("==", TTL)),
			HaveResponseType(ResponseTypeCUSTOMDNS),
			HaveReason("CUSTOM DNS"),
			HaveReturnCode(dns.RcodeSuccess),
		)
	}

	It("is enabled by clientMapping alone", func() {
		cfg.Mapping = nil
		cfg.Zone = config.ZoneFileDNS{}

		Expect(NewCustomDNSResolver(cfg).IsEnabled()).Should(BeTrue())
	})

	Describe("choosing the client's entry", func() {
		DescribeTable("answers from the most specific matching entry",
			func(ip string, names []string, answer string) {
				Expect(resolve("www.domain.io.", A, ip, names...)).
					Should(answeredWith("www.domain.io.", A, answer))
				m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
			},
			Entry("the only matching CIDR", "192.168.69.1", nil, "192.168.1.75"),
			Entry("the longest of two matching CIDRs", "192.168.68.9", nil, "192.168.1.76"),
			Entry("the exact IP over every CIDR", "192.168.68.5", nil, "192.168.1.77"),
			Entry("a client name over the exact IP", "192.168.68.5", []string{"laptop"}, "10.0.0.1"),
			Entry("a client name, case-insensitively", other, []string{"TABLET"}, "10.0.0.1"),
			Entry("a later client name of the request", other, []string{"unknown", "laptop"}, "10.0.0.1"),
			Entry("the exact IP over a client-name wildcard", "192.168.68.5", []string{"phone-1"}, "192.168.1.77"),
			Entry("a client-name wildcard over a CIDR", "192.168.69.1", []string{"phone-1"}, "10.0.0.2"),
			Entry("a client-name wildcard alone", other, []string{"phone-1"}, "10.0.0.2"),
		)

		It("matches IPv6 clients by CIDR and by exact IP in any spelling", func() {
			Expect(resolve("www.domain.io.", AAAA, "2001:db8:68::1")).
				Should(answeredWith("www.domain.io.", AAAA, "2001:db8::75"))
			Expect(resolve("www.domain.io.", AAAA, "2001:db8:68::abcd")).
				Should(answeredWith("www.domain.io.", AAAA, "2001:db8::77"))
		})

		It("leaves clients outside every entry to the global mapping and the next resolver", func() {
			Expect(resolve("printer.lan.", A, other)).Should(answeredWith("printer.lan.", A, "192.168.178.3"))
			m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)

			Expect(resolve("www.domain.io.", A, other)).Should(HaveResponseType(ResponseTypeRESOLVED))
			m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
		})

		It("applies one entry only: an empty exact-IP entry carves a client out of its CIDR's", func() {
			// 192.168.70.9 is in 192.168.68.0/22
			Expect(resolve("www.domain.io.", A, "192.168.70.9")).Should(HaveResponseType(ResponseTypeRESOLVED))
			Expect(resolve("ha.home.lan.", A, "192.168.70.9")).
				Should(answeredWith("ha.home.lan.", A, "192.168.178.10"))
		})

		It("does not fall back to a less specific entry for names the chosen one lacks", func() {
			// the /24 entry has no home.lan, the /22 one does
			Expect(resolve("x.home.lan.", A, "192.168.68.9")).Should(HaveResponseType(ResponseTypeRESOLVED))
			m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
		})
	})

	Describe("the client's mapping and the global one", func() {
		// the client at 192.168.69.1 has the 192.168.68.0/22 entry
		const client = "192.168.69.1"

		It("answers a more specific global name over a parent key of the client's", func() {
			// global ha.home.lan, client home.lan
			Expect(resolve("ha.home.lan.", A, client)).Should(answeredWith("ha.home.lan.", A, "192.168.178.10"))
			Expect(resolve("sub.ha.home.lan.", A, client)).
				Should(answeredWith("sub.ha.home.lan.", A, "192.168.178.10"))
		})

		It("answers the client's key over the global one of the same name", func() {
			Expect(resolve("printer.lan.", A, client)).Should(answeredWith("printer.lan.", A, "192.168.68.3"))
		})

		It("answers a more specific client name over a global parent key", func() {
			// client vpn.corp.lan, global corp.lan
			Expect(resolve("vpn.corp.lan.", A, client)).Should(answeredWith("vpn.corp.lan.", A, "192.168.68.30"))
			Expect(resolve("x.vpn.corp.lan.", A, client)).Should(answeredWith("x.vpn.corp.lan.", A, "192.168.68.30"))
			Expect(resolve("mail.corp.lan.", A, client)).Should(answeredWith("mail.corp.lan.", A, "192.168.178.30"))
		})

		It("answers from a client parent key where no level has a global name", func() {
			Expect(resolve("x.home.lan.", A, client)).Should(answeredWith("x.home.lan.", A, "192.168.68.22"))
			Expect(resolve("sub.www.domain.io.", A, client)).
				Should(answeredWith("sub.www.domain.io.", A, "192.168.1.75"))
		})

		It("falls back to the global mapping for names the client's mapping lacks", func() {
			Expect(resolve("shared.lan.", A, client)).Should(answeredWith("shared.lan.", A, "192.168.178.20"))
			m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
		})

		It("leaves other clients' answers unchanged", func() {
			Expect(resolve("x.home.lan.", A, other)).Should(HaveResponseType(ResponseTypeRESOLVED))
			Expect(resolve("vpn.corp.lan.", A, other)).Should(answeredWith("vpn.corp.lan.", A, "192.168.178.30"))
			Expect(resolve("printer.lan.", AAAA, other)).Should(answeredWith("printer.lan.", AAAA, "2001:db8::3"))
		})

		nodata := SatisfyAll(
			HaveNoAnswer(),
			HaveSOARecord(TTL, TTL),
			HaveResponseType(ResponseTypeCUSTOMDNS),
			HaveReturnCode(dns.RcodeSuccess),
		)

		When("filterUnmappedTypes is true", func() {
			It("answers an unmapped type of a client-only name with NODATA", func() {
				Expect(resolve("www.domain.io.", AAAA, client)).Should(nodata)
				Expect(resolve("x.home.lan.", AAAA, client)).Should(nodata)
				m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
			})

			It("answers an unmapped type of a client name with NODATA, even where the global name has it", func() {
				Expect(resolve("printer.lan.", AAAA, client)).Should(nodata)
				m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
			})
		})

		When("filterUnmappedTypes is false", func() {
			BeforeEach(func() { cfg.FilterUnmappedTypes = false })

			It("forwards an unmapped type of a client-only name to the next resolver", func() {
				Expect(resolve("www.domain.io.", AAAA, client)).Should(HaveResponseType(ResponseTypeRESOLVED))
				m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
			})

			It("forwards an unmapped type of a client name to the next resolver, not to the global name", func() {
				Expect(resolve("printer.lan.", AAAA, client)).Should(HaveResponseType(ResponseTypeRESOLVED))
				m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
			})
		})
	})

	Describe("CNAME", func() {
		It("resolves a global CNAME's target as the client sees it", func() {
			Expect(resolve("alias.lan.", A, "192.168.69.1")).
				Should(SatisfyAll(
					WithTransform(ToAnswer, SatisfyAll(
						HaveLen(2),
						ContainElements(
							BeDNSRecord("alias.lan.", CNAME, "www.domain.io."),
							BeDNSRecord("www.domain.io.", A, "192.168.1.75"),
						),
					)),
					HaveResponseType(ResponseTypeCUSTOMDNS),
				))
			m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
		})

		It("keeps the client's view along the chain, parent keys included", func() {
			Expect(resolve("home-alias.lan.", A, "192.168.69.1")).
				Should(WithTransform(ToAnswer, ConsistOf(
					BeDNSRecord("home-alias.lan.", CNAME, "x.home.lan."),
					BeDNSRecord("x.home.lan.", A, "192.168.68.22"),
				)))
			m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
		})

		It("resolves the target through the chain for other clients", func() {
			Expect(resolve("alias.lan.", A, other)).
				Should(WithTransform(ToAnswer, ConsistOf(BeDNSRecord("alias.lan.", CNAME, "www.domain.io."))))
			m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
		})
	})

	Describe("rewrite", func() {
		BeforeEach(func() {
			cfg.Rewrite = map[string]string{"domain.test": "domain.io"}
		})

		It("applies to the client's mapping and restores the queried name", func() {
			Expect(resolve("www.domain.test.", A, "192.168.69.1")).
				Should(answeredWith("www.domain.test.", A, "192.168.1.75"))
		})
	})

	Describe("reverse lookups", func() {
		ptr := func(ip string) string {
			r, _ := dns.ReverseAddr(ip)

			return r
		}

		It("answers the client's own addresses for that client only", func() {
			Expect(resolve(ptr("192.168.1.75"), PTR, "192.168.69.1")).
				Should(SatisfyAll(
					BeDNSRecord(ptr("192.168.1.75"), PTR, "www.domain.io."),
					HaveResponseType(ResponseTypeCUSTOMDNS),
				))

			Expect(resolve(ptr("192.168.1.75"), PTR, other)).Should(HaveResponseType(ResponseTypeRESOLVED))
		})

		It("answers global addresses unless the client's mapping holds the same name", func() {
			Expect(resolve(ptr("192.168.178.20"), PTR, "192.168.69.1")).
				Should(BeDNSRecord(ptr("192.168.178.20"), PTR, "shared.lan."))
			// below the client's home.lan, but more specific: it still resolves globally
			Expect(resolve(ptr("192.168.178.10"), PTR, "192.168.69.1")).
				Should(BeDNSRecord(ptr("192.168.178.10"), PTR, "ha.home.lan."))
			m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)

			// printer.lan resolves to the client's own address for this client
			Expect(resolve(ptr("192.168.178.3"), PTR, "192.168.69.1")).Should(HaveResponseType(ResponseTypeRESOLVED))
			Expect(resolve(ptr("192.168.68.3"), PTR, "192.168.69.1")).
				Should(BeDNSRecord(ptr("192.168.68.3"), PTR, "printer.lan."))

			Expect(resolve(ptr("192.168.178.3"), PTR, other)).
				Should(BeDNSRecord(ptr("192.168.178.3"), PTR, "printer.lan."))
		})

		It("keeps LookupReverse, which names clients, to the global mapping", func() {
			Expect(sut.LookupReverse(net.ParseIP("192.168.1.75"))).Should(BeNil())
			Expect(sut.LookupReverse(net.ParseIP("192.168.178.20"))).Should(ConsistOf("shared.lan"))
		})
	})

	Describe("in front of the cache", func() {
		var upstream *mockResolver

		JustBeforeEach(func() {
			cacheCfg := config.Caching{}
			Expect(defaults.Set(&cacheCfg)).Should(Succeed())

			caching, err := NewCachingResolver(ctx, cacheCfg, config.DNSSEC{}, nil)
			Expect(err).Should(Succeed())

			upstream = &mockResolver{
				AnswerFn: func(qType dns.Type, qName string) (*dns.Msg, error) {
					return util.NewMsgWithAnswer(qName, 300, qType, "203.0.113.1")
				},
			}
			upstream.On("Resolve", mock.Anything)

			sut = NewCustomDNSResolver(cfg)
			Chain(sut, caching, upstream)
		})

		expectUpstreamAnswer := func(rType ResponseType) {
			Expect(resolve("www.domain.io.", A, other)).
				Should(SatisfyAll(
					BeDNSRecord("www.domain.io.", A, "203.0.113.1"),
					HaveResponseType(rType),
				))
		}

		It("never stores a client's answer for other clients", func() {
			Expect(resolve("www.domain.io.", A, "192.168.69.1")).
				Should(answeredWith("www.domain.io.", A, "192.168.1.75"))

			expectUpstreamAnswer(ResponseTypeRESOLVED)
			expectUpstreamAnswer(ResponseTypeCACHED)

			Expect(resolve("www.domain.io.", A, "192.168.69.1")).
				Should(answeredWith("www.domain.io.", A, "192.168.1.75"))
			upstream.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
		})

		It("never serves another client's cached answer to a client with its own", func() {
			expectUpstreamAnswer(ResponseTypeRESOLVED)
			expectUpstreamAnswer(ResponseTypeCACHED)

			Expect(resolve("www.domain.io.", A, "192.168.69.1")).
				Should(answeredWith("www.domain.io.", A, "192.168.1.75"))
			upstream.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
		})
	})
})
