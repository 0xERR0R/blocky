package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/resolver"

	"github.com/miekg/dns"
)

// These benchmarks exercise the DNS request hot path end-to-end (request
// construction + resolver-chain plumbing in Server.resolve), reporting
// allocations/op. They deliberately use a trivial terminal resolver so the
// measured allocations come from blocky's own per-request machinery
// (uuid, question formatting, logging plumbing, context wrapping, response
// post-processing) rather than from real upstream I/O.
//
// Run with:
//
//	go test -run=^$ -bench=HotPath -benchmem ./server/

// benchTerminalResolver is a minimal ChainedResolver that returns a freshly
// built answer, standing in for the upstream resolver at the end of the chain.
type benchTerminalResolver struct {
	resolver.NextResolver
}

func (benchTerminalResolver) Type() string           { return "bench_terminal" }
func (r benchTerminalResolver) String() string       { return r.Type() }
func (benchTerminalResolver) IsEnabled() bool        { return true }
func (benchTerminalResolver) LogConfig(*slog.Logger) {}

// benchAnswerRR is parsed once; the terminal resolver clones it per call so the
// benchmark measures response handling, not repeated zone-file parsing (which
// would not happen in production, where the upstream returns a parsed message).
var benchAnswerRR = func() dns.RR {
	rr, err := dns.NewRR("example.com. 60 IN A 127.0.0.1")
	if err != nil {
		panic(err)
	}

	return rr
}()

func (benchTerminalResolver) Resolve(_ context.Context, req *model.Request) (*model.Response, error) {
	resp := new(dns.Msg)
	resp.SetReply(req.Req)

	for range req.Req.Question {
		resp.Answer = append(resp.Answer, dns.Copy(benchAnswerRR))
	}

	return &model.Response{Res: resp, RType: model.ResponseTypeRESOLVED, Reason: ""}, nil
}

// newBenchServer builds a Server backed by a chain ending in the terminal
// resolver, without the full NewServer bootstrap (no sockets, no real
// upstreams).
func newBenchServer(chain resolver.ChainedResolver) *Server {
	cfg := config.Config{}
	cfg.Upstreams.Timeout = config.Duration(2 * time.Second)

	return &Server{
		queryResolver: chain,
		cfg:           &cfg,
	}
}

func benchQuery(name string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeA)

	return msg
}

// benchmarkHotPath runs the full per-request path: build the request (the same
// path used by newRequestFromDNS) and resolve it through the chain.
func benchmarkHotPath(b *testing.B, level slog.Level, chain resolver.ChainedResolver) {
	b.Helper()

	// Real logger at the given level, but discard output: we measure the
	// per-request plumbing, not the cost of writing bytes to a terminal.
	log.ConfigureForTest(io.Discard)
	log.SetLevel(level)

	srv := newBenchServer(chain)
	clientIP := net.ParseIP("192.168.178.1")
	query := benchQuery("example.com")

	ctx := context.Background()

	b.ReportAllocs()

	for b.Loop() {
		reqCtx, req := newRequest(ctx, clientIP, "", model.RequestProtocolUDP, query.Copy())

		resp, err := srv.resolve(reqCtx, req)
		if err != nil {
			b.Fatal(err)
		}

		runtimeSink = resp
	}
}

// runtimeSink keeps the compiler from optimizing the benchmark result away.
var runtimeSink *model.Response

// BenchmarkHotPath_InfoLevel is the common production case (debug/trace off).
func BenchmarkHotPath_InfoLevel(b *testing.B) {
	chain := resolver.Chain(&benchTerminalResolver{})
	benchmarkHotPath(b, slog.LevelInfo, chain)
}

// BenchmarkHotPath_DebugLevel shows the cost when debug lines are emitted.
func BenchmarkHotPath_DebugLevel(b *testing.B) {
	chain := resolver.Chain(&benchTerminalResolver{})
	benchmarkHotPath(b, slog.LevelDebug, chain)
}
