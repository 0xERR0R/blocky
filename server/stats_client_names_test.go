package server

import (
	"context"
	"net"
	"time"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/resolver"
	"github.com/0xERR0R/blocky/stats"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Queries that are answered above the client-name lookup (filtered query types,
// non-FQDN names, rate-limited clients) must still be attributed to the client's
// name in the statistics, otherwise the same client shows up twice in the
// top-clients list: once by name, once by raw IP. See #2152.
var _ = Describe("Client identity for queries answered at the head of the chain", func() {
	const clientName = "laptop"

	var clientIP = net.ParseIP("192.168.1.11")

	newServer := func(ctx context.Context, adapt func(cfg *config.Config)) *Server {
		GinkgoHelper()

		cfg := &config.Config{
			Upstreams: config.Upstreams{
				Groups: map[string][]config.Upstream{
					"default": {config.Upstream{Net: config.NetProtocolTcpUdp, Host: "4.4.4.4", Port: 53}},
				},
			},
			Blocking:     config.Blocking{BlockType: "zeroIp"},
			Statistics:   config.Statistics{Enable: true},
			ClientLookup: config.ClientLookup{ClientnameIPMapping: map[string][]net.IP{clientName: {clientIP}}},
			Ports:        config.Ports{DOHPath: "/dns-query"},
		}

		adapt(cfg)

		srv, err := NewServer(ctx, cfg)
		Expect(err).Should(Succeed())

		return srv
	}

	topClients := func(srv *Server) func() []stats.NameCount {
		GinkgoHelper()

		provider, err := resolver.GetFromChainWithType[api.StatsProvider](srv.queryResolver)
		Expect(err).Should(Succeed())

		return func() []stats.NameCount {
			return provider.Stats().TopClients
		}
	}

	DescribeTable("records the client name, not the client IP",
		func(ctx context.Context, adapt func(cfg *config.Config), question string, qType dns.Type,
			expectedRType model.ResponseType,
		) {
			srv := newServer(ctx, adapt)

			resp, err := srv.queryResolver.Resolve(ctx, &model.Request{
				ClientIP:  clientIP,
				Req:       util.NewMsgWithQuestion(question, qType),
				RequestTS: time.Now(),
			})

			Expect(err).Should(Succeed())
			Expect(resp.RType).Should(Equal(expectedRType))

			Eventually(topClients(srv)).Should(ConsistOf(stats.NameCount{Name: clientName, Count: 1}))
		},
		Entry("query type filtered by the filtering resolver",
			func(cfg *config.Config) {
				cfg.Filtering = config.Filtering{QueryTypes: config.NewQTypeSet(dns.Type(dns.TypeAAAA))}
			},
			"example.com.", dns.Type(dns.TypeAAAA), model.ResponseTypeFILTERED),
		Entry("non-FQDN query rejected by the fqdnOnly resolver",
			func(cfg *config.Config) {
				cfg.FQDNOnly = config.FQDNOnly{Enable: true}
			},
			"example.", dns.Type(dns.TypeA), model.ResponseTypeNOTFQDN),
	)

	// The rate limiter deliberately stays above the client-name lookup so that its bucket
	// key remains the connection's source IP (see the chain in createQueryResolver), which
	// leaves the dropped queries without a client name.
	It("attributes a rate-limited query to the client IP", func(ctx context.Context) {
		srv := newServer(ctx, func(cfg *config.Config) {
			cfg.RateLimit = config.RateLimit{Enable: true, Rate: 1, Burst: 1, IPv4Prefix: 32, IPv6Prefix: 64}
			// answered locally, so the query that passes the limiter needs no upstream
			cfg.CustomDNS = config.CustomDNS{
				Mapping: config.CustomDNSMapping{"example.com": {&dns.A{A: net.ParseIP("192.168.1.99")}}},
			}
		})

		// the first query passes the limiter, the second one is dropped by it
		for range 2 {
			_, _ = srv.queryResolver.Resolve(ctx, &model.Request{
				ClientIP:  clientIP,
				Req:       util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA)),
				RequestTS: time.Now(),
			})
		}

		Eventually(topClients(srv)).Should(ConsistOf(
			stats.NameCount{Name: clientName, Count: 1},
			stats.NameCount{Name: clientIP.String(), Count: 1},
		))
	})
})
