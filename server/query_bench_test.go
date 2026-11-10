package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/miekg/dns"
)

// BenchmarkQuery measures what a query costs between the bytes received from the client
// and the bytes sent back: unpacking it, the whole resolver chain as NewServer builds it,
// and packing the response. The network I/O with the client is not included.
//
//	go test -run=^$ -bench=BenchmarkQuery -benchmem ./server/
func BenchmarkQuery(b *testing.B) {
	// answered from the cache
	b.Run("cached", func(b *testing.B) {
		benchmarkQueries(b, benchScenario{nameFormat: "host%d.allowed.example.", answer: benchUpstreamAnswer})
	})

	// answered from the denylist
	b.Run("blocked", func(b *testing.B) {
		benchmarkQueries(b, benchScenario{nameFormat: "ads%d.blocked.example.", answer: "0.0.0.0"})
	})

	// sent to two upstreams on the loopback interface
	b.Run("forwarded", func(b *testing.B) {
		benchmarkQueries(b, benchScenario{
			nameFormat: "host%d.allowed.example.",
			answer:     benchUpstreamAnswer,
			forwarded:  true,
			configure:  func(cfg *config.Config) { cfg.Caching.MaxCachingTime = -1 },
		})
	})
}

const (
	benchDenylistSize = 200_000
	benchQueryCount   = 1024

	// benchUpstreamAnswer is the first address the upstreams answer with
	benchUpstreamAnswer = "192.0.2.10"

	// benchTimedID is the ID of the queries the benchmark times. Blocky forwards a query
	// with its ID, which tells the upstreams the timed queries from the others.
	benchTimedID = 0xb10c
)

// benchScenario is a kind of query, and how to tell that blocky answers it as intended.
type benchScenario struct {
	// nameFormat makes the name of the query with a given number
	nameFormat string
	// answer is the first address of each answer
	answer string
	// forwarded reports that each query reaches an upstream. Otherwise none does.
	forwarded bool
	// configure changes the configuration of the server
	configure func(*config.Config)
}

// check fails the benchmark unless response is the answer of the scenario.
func (s benchScenario) check(b *testing.B, response *dns.Msg) {
	b.Helper()

	if !isAnswered(response) {
		b.Fatalf("no answer: %v", response)
	}

	if a, ok := response.Answer[0].(*dns.A); !ok || a.A.String() != s.answer {
		b.Fatalf("answer %s, want the address %s", response.Answer[0], s.answer)
	}
}

func isAnswered(response *dns.Msg) bool {
	return response != nil && response.Rcode == dns.RcodeSuccess && len(response.Answer) > 0
}

func benchmarkQueries(b *testing.B, scenario benchScenario) {
	b.Helper()

	srv, timedForwarded := benchServer(b, scenario.configure)

	ctx := context.Background()
	w := &benchResponseWriter{client: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 40000}}

	serve := func(packed []byte) *dns.Msg {
		query := new(dns.Msg)
		if err := query.Unpack(packed); err != nil {
			b.Fatal(err)
		}

		w.response = nil
		srv.OnRequest(ctx, w, query)

		return w.response
	}

	// The first round fills the caches. The second one gets the answers the timed
	// queries get, and checks them.
	warmUp := benchQueries(b, scenario, benchTimedID+1)

	for _, query := range warmUp {
		serve(query)
	}

	for _, query := range warmUp {
		scenario.check(b, serve(query))
	}

	var (
		queries    = benchQueries(b, scenario, benchTimedID)
		unanswered int
	)

	// the queries the server sent at its start had random IDs
	timedForwarded.Store(0)

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		if !isAnswered(serve(queries[i%len(queries)])) {
			unanswered++
		}
	}

	if unanswered > 0 {
		b.Fatalf("%d of %d queries got no answer", unanswered, b.N)
	}

	// a faster way to answer the wrong way is no gain
	forwarded := timedForwarded.Load()
	if (scenario.forwarded && forwarded < int64(b.N)) || (!scenario.forwarded && forwarded > 0) {
		b.Fatalf("%d of %d queries reached an upstream", forwarded, b.N)
	}
}

// benchQueries returns the packed queries of the scenario, all with the given ID.
func benchQueries(b *testing.B, scenario benchScenario, id uint16) [][]byte {
	b.Helper()

	queries := make([][]byte, benchQueryCount)

	for i := range queries {
		query := new(dns.Msg)
		query.SetQuestion(fmt.Sprintf(scenario.nameFormat, i), dns.TypeA)
		query.SetEdns0(dns.DefaultMsgSize, false)
		query.Id = id

		packed, err := query.Pack()
		if err != nil {
			b.Fatal(err)
		}

		queries[i] = packed
	}

	return queries
}

// benchServer returns a server without listeners: default configuration, a denylist and
// two upstreams that answer from memory. It also returns the count of the timed queries
// the upstreams got.
func benchServer(b *testing.B, configure func(*config.Config)) (*Server, *atomic.Int64) {
	b.Helper()

	timedForwarded := new(atomic.Int64)

	log.Log().SetOutput(io.Discard)

	var denylist strings.Builder
	for i := range benchDenylistSize {
		fmt.Fprintf(&denylist, "ads%d.blocked.example\n", i)
	}

	denylistFile := filepath.Join(b.TempDir(), "denylist.txt")
	if err := os.WriteFile(denylistFile, []byte(denylist.String()), 0o600); err != nil {
		b.Fatal(err)
	}

	cfg, err := config.WithDefaults[config.Config]()
	if err != nil {
		b.Fatal(err)
	}

	cfg.Ports.DNS = nil
	cfg.Upstreams.Groups = map[string][]config.Upstream{
		"default": {benchUpstream(b, timedForwarded), benchUpstream(b, timedForwarded)},
	}
	cfg.Blocking.Denylists = map[string][]config.BytesSource{"ads": config.NewBytesSources(denylistFile)}
	cfg.Blocking.ClientGroupsBlock = map[string][]string{"default": {"ads"}}
	cfg.Blocking.Loading.RefreshPeriod = -1
	cfg.Caching.MinCachingTime = config.Duration(time.Hour)
	cfg.QueryLog.Type = config.QueryLogTypeNone

	if configure != nil {
		configure(&cfg)
	}

	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)

	srv, err := NewServer(ctx, &cfg)
	if err != nil {
		b.Fatal(err)
	}

	return srv, timedForwarded
}

// benchUpstream starts an upstream that answers every A query with two addresses, and
// counts the timed queries it gets.
func benchUpstream(b *testing.B, timedQueries *atomic.Int64) config.Upstream {
	b.Helper()

	conn, err := new(net.ListenConfig).ListenPacket(b.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}

	b.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, dns.DefaultMsgSize)

		for {
			n, client, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}

			query := new(dns.Msg)
			if query.Unpack(buf[:n]) != nil || len(query.Question) != 1 {
				continue
			}

			if query.Id == benchTimedID {
				timedQueries.Add(1)
			}

			response := new(dns.Msg)
			response.SetReply(query)

			if question := query.Question[0]; question.Qtype == dns.TypeA {
				for _, ip := range []net.IP{net.ParseIP(benchUpstreamAnswer), {192, 0, 2, 11}} {
					response.Answer = append(response.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   ip,
					})
				}
			}

			if packed, err := response.Pack(); err == nil {
				_, _ = conn.WriteTo(packed, client)
			}
		}
	}()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		b.Fatalf("unexpected listener address %s", conn.LocalAddr())
	}

	return config.Upstream{Net: config.NetProtocolTcpUdp, Host: "127.0.0.1", Port: uint16(addr.Port)}
}

// benchResponseWriter packs responses as the DNS server does, and keeps the last one.
type benchResponseWriter struct {
	client   net.Addr
	response *dns.Msg
}

func (w *benchResponseWriter) LocalAddr() net.Addr         { return w.client }
func (w *benchResponseWriter) RemoteAddr() net.Addr        { return w.client }
func (w *benchResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *benchResponseWriter) Close() error                { return nil }
func (w *benchResponseWriter) TsigStatus() error           { return nil }
func (w *benchResponseWriter) TsigTimersOnly(bool)         {}
func (w *benchResponseWriter) Hijack()                     {}

func (w *benchResponseWriter) WriteMsg(m *dns.Msg) error {
	w.response = m

	_, err := m.Pack()

	return err
}
