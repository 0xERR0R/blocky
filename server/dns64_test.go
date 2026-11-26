package server

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/resolver"
	"github.com/creasty/defaults"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Validating DNS64 chain", func() {
	It("finishes validation retries before synthesis and synthesizes from cached inputs", func(ctx context.Context) {
		const allowed = "outside.example.com."
		const anchored = "signed.example.com."
		var allowedA, anchoredAAAA, anchoredA atomic.Int32
		upstream := resolver.NewMockUDPUpstreamServer().WithAnswerFn(func(q *dns.Msg) *dns.Msg {
			m := new(dns.Msg).SetReply(q)
			question := q.Question[0]
			switch question.Qtype {
			case dns.TypeAAAA:
				if question.Name == anchored {
					anchoredAAAA.Add(1)
				}
			case dns.TypeA:
				switch question.Name {
				case allowed:
					allowedA.Add(1)
				case anchored:
					anchoredA.Add(1)
				}
				m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 1)}}
			}

			return m
		})
		var cfg config.Config
		Expect(defaults.Set(&cfg)).Should(Succeed())
		cfg.Ports.DNS = nil
		cfg.DNS64.Enable = true
		cfg.DNSSEC.Validate = true
		cfg.DNSSEC.TrustAnchors = []string{anchored + " 300 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3"}
		cfg.Upstreams.Groups = map[string][]config.Upstream{"default": {upstream.Start()}}
		cfg.Conditional.Mapping.Upstreams = map[string][]config.Upstream{"private.signed.example.com": cfg.Upstreams.Groups["default"]}
		DeferCleanup(upstream.Close)
		srv, err := NewServer(ctx, &cfg)
		Expect(err).Should(Succeed())
		DeferCleanup(func() { Expect(srv.Stop(ctx)).Should(Succeed()) })
		query := func(name string, do, cd bool) *model.Response {
			q := new(dns.Msg).SetQuestion(name, dns.TypeAAAA)
			q.SetEdns0(1232, do)
			q.CheckingDisabled = cd
			r, err := srv.queryResolver.Resolve(ctx, &model.Request{Req: q, Protocol: model.RequestProtocolUDP})
			Expect(err).Should(Succeed())

			return r
		}
		Expect(query(anchored, false, false).Res.Rcode).Should(Equal(dns.RcodeServerFailure))
		Expect(anchoredAAAA.Load()).Should(BeEquivalentTo(2))
		Expect(anchoredA.Load()).Should(BeZero())
		unchecked := query(anchored, true, true)
		Expect(unchecked.Res.Rcode).Should(Equal(dns.RcodeSuccess))
		Expect(unchecked.Res.Answer).Should(BeEmpty())
		Expect(anchoredA.Load()).Should(BeZero())
		cd := query(anchored, false, true)
		Expect(cd.RType).Should(Equal(model.ResponseTypeSYNTHESIZED))
		Expect(cd.Res.CheckingDisabled).Should(BeTrue())
		Expect(cd.Res.AuthenticatedData).Should(BeFalse())
		Expect(query("private.signed.example.com.", false, false).RType).Should(Equal(model.ResponseTypeSYNTHESIZED))
		for _, do := range []bool{false, true} {
			r := query(allowed, do, false)
			Expect(r.RType).Should(Equal(model.ResponseTypeSYNTHESIZED))
			Expect(r.Res.AuthenticatedData).Should(BeFalse())
			Expect(r.Res.Answer).Should(HaveLen(1))
			Expect(r.Res.Answer[0].(*dns.AAAA).AAAA.String()).Should(Equal("64:ff9b::c000:201"))
		}
		Expect(allowedA.Load()).Should(BeEquivalentTo(1))
	})
})
