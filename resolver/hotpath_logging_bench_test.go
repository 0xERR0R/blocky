package resolver

import (
	"context"
	"testing"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// loggingPassthrough mimics a real chained resolver's per-request logger plumbing:
// it derives the prefixed context logger (`r.log(ctx)`) exactly as every resolver does
// at the top of Resolve, discards the logger (nothing is logged at Info level), and
// delegates to the next resolver. A chain of these measures the Tier-1 cost: the
// logrus Entry copies + Data-map clone + context.WithValue paid per resolver per
// request regardless of log level.
type loggingPassthrough struct {
	typed
	NextResolver
}

func (loggingPassthrough) IsEnabled() bool         { return true }
func (loggingPassthrough) LogConfig(*logrus.Entry) {}

func (r *loggingPassthrough) Resolve(ctx context.Context, req *model.Request) (*model.Response, error) {
	ctx, logger := r.log(ctx)
	_ = logger // not used at Info level — this is the whole point

	return r.next.Resolve(ctx, req)
}

// BenchmarkChainLoggingPlumbing measures the per-request logger overhead of a chain
// of resolvers at the default (Info) level, where Debug/Trace lines never print but
// the prefixed context logger is still rebuilt in every resolver.
//
//	go test -run=^$ -bench=BenchmarkChainLoggingPlumbing -benchmem ./resolver/
func BenchmarkChainLoggingPlumbing(b *testing.B) {
	const chainDepth = 15 // ~ resolvers traversed on a cache miss

	// production default: Info — Debug/Trace disabled
	prev := log.Log().Level
	log.Log().SetLevel(logrus.InfoLevel)
	b.Cleanup(func() { log.Log().SetLevel(prev) })

	resolvers := make([]Resolver, 0, chainDepth+1)
	for i := range chainDepth {
		resolvers = append(resolvers, &loggingPassthrough{typed: withType(chainNodeName(i))})
	}
	resolvers = append(resolvers, benchBackend{})

	sut := Chain(resolvers...)

	req := &model.Request{
		Req:      util.NewMsgWithQuestion("example.com.", dns.Type(dns.TypeA)),
		Protocol: model.RequestProtocolUDP,
	}

	// seed the request context with the same fields the server attaches per request
	// (req_id / question / client_ip), so the cloned Data map has a realistic size.
	baseCtx, _ := log.CtxWithFields(context.Background(), logrus.Fields{
		"req_id":    "00000000-0000-0000-0000-000000000000",
		"question":  "A (example.com.)",
		"client_ip": "192.168.1.100",
	})

	b.ReportAllocs()

	for b.Loop() {
		_, _ = sut.Resolve(baseCtx, req)
	}
}

// BenchmarkDebugFieldBuild_Avoided measures the per-call cost of building the
// answer log field (util.Obfuscate(util.AnswerToString(...))) that the IsLevelEnabled
// guards now skip on the cache-miss path when Debug is disabled (the production default).
// Each guarded site (upstream logResponse, parallel_best, conditional) avoids this work.
//
//	go test -run=^$ -bench=BenchmarkDebugFieldBuild_Avoided -benchmem ./resolver/
func BenchmarkDebugFieldBuild_Avoided(b *testing.B) {
	answer := []dns.RR{
		mustRR("example.com. 3600 IN A 1.2.3.4"),
		mustRR("example.com. 3600 IN A 5.6.7.8"),
	}

	b.ReportAllocs()

	for b.Loop() {
		_ = util.Obfuscate(util.AnswerToString(answer))
	}
}

func mustRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}

	return rr
}

func chainNodeName(i int) string {
	names := []string{
		"stats", "rate_limiting", "filtering", "fqdn_only", "client_names",
		"ede", "query_logging", "metrics", "custom_dns", "hosts_file",
		"rebinding", "blocking", "dnssec", "caching", "conditional",
	}

	return names[i%len(names)]
}
