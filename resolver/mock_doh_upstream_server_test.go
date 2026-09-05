package resolver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/onsi/ginkgo/v2"
)

// dohConnKey carries the accepted connection into the handler, so it can tell
// which connection a request arrived on.
type dohConnKey struct{}

// MockDoHUpstreamServer is a mock DNS-over-HTTPS server for testing how the DoH
// upstream client copes with connections the server has closed.
//
// A request arriving on a *poisoned* connection is answered by closing that
// connection without a response. That is what blocky sees when it sends a query
// over a keep-alive connection the upstream has already closed: the write lands
// in a dead socket and the read returns EOF, with the query never served.
// KillOpenConns poisons every connection currently open, modelling an upstream
// that dropped its idle connections; KillAll poisons new connections too,
// modelling one that refuses to serve at all.
type MockDoHUpstreamServer struct {
	server *httptest.Server

	callCount atomic.Int32
	connCount atomic.Int32
	killAll   atomic.Bool

	// barrier holds the first barrierRemaining requests until all of them have
	// arrived, so they cannot be served one after another on a single connection.
	barrier          atomic.Pointer[chan struct{}]
	barrierRemaining atomic.Int32

	answerFn func(request *dns.Msg) (response *dns.Msg)

	// mu guards conns, the set of open connections and whether each is poisoned.
	mu    sync.Mutex
	conns map[net.Conn]bool
}

func NewMockDoHUpstreamServer() *MockDoHUpstreamServer {
	srv := &MockDoHUpstreamServer{conns: make(map[net.Conn]bool)}
	ginkgo.DeferCleanup(srv.Close)

	return srv
}

func (m *MockDoHUpstreamServer) WithAnswerRR(answers ...string) *MockDoHUpstreamServer {
	m.answerFn = rrAnswerFn(answers...)

	return m
}

// WithConcurrentRequests makes the first n requests block until all n have
// arrived. The client can then not serve them on one connection, so the test
// starts from a keep-alive pool holding n connections.
func (m *MockDoHUpstreamServer) WithConcurrentRequests(n int) *MockDoHUpstreamServer {
	barrier := make(chan struct{})
	m.barrier.Store(&barrier)
	m.barrierRemaining.Store(int32(n))

	return m
}

// awaitBarrier blocks until the configured number of requests have arrived. Once
// released the barrier stays open, so later requests pass straight through.
func (m *MockDoHUpstreamServer) awaitBarrier() {
	barrier := m.barrier.Load()
	if barrier == nil {
		return
	}

	if m.barrierRemaining.Add(-1) == 0 {
		close(*barrier)
	}

	<-*barrier
}

// KillOpenConns poisons every currently open connection: the next request on
// each is answered by closing it. Connections opened afterwards stay healthy.
func (m *MockDoHUpstreamServer) KillOpenConns() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for conn := range m.conns {
		m.conns[conn] = true
	}
}

// KillAll makes the server close every connection, including new ones, without
// ever answering.
func (m *MockDoHUpstreamServer) KillAll() {
	m.killAll.Store(true)

	m.KillOpenConns()
}

func (m *MockDoHUpstreamServer) GetCallCount() int {
	return int(m.callCount.Load())
}

// GetConnCount returns how many connections the server has accepted, so a test
// can tell a reused connection from a fresh one.
func (m *MockDoHUpstreamServer) GetConnCount() int {
	return int(m.connCount.Load())
}

func (m *MockDoHUpstreamServer) poisoned(conn net.Conn) bool {
	if m.killAll.Load() {
		return true
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	return m.conns[conn]
}

func (m *MockDoHUpstreamServer) trackConn(conn net.Conn, state http.ConnState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch state {
	case http.StateNew:
		m.connCount.Add(1)

		m.conns[conn] = false
	case http.StateClosed, http.StateHijacked:
		delete(m.conns, conn)
	case http.StateActive, http.StateIdle:
	}
}

func (m *MockDoHUpstreamServer) handle(w http.ResponseWriter, r *http.Request) {
	// Read the request fully before deciding what to do, so a killed connection
	// fails while the client waits for the response - as it does in the wild -
	// rather than while it is still writing.
	body, err := io.ReadAll(r.Body)
	util.FatalOnError("can't read request: ", err)

	// The mock is HTTP/1.1-only by construction (see Start). Both the kill path
	// below, which needs Hijacker, and the one-request-per-connection assumption
	// the specs rely on would break silently under HTTP/2 multiplexing, so say so
	// loudly rather than failing in confusing ways.
	if r.ProtoMajor != 1 {
		util.FatalOnError("mock DoH upstream: ", fmt.Errorf("expected HTTP/1.1, got %s", r.Proto))
	}

	conn, _ := r.Context().Value(dohConnKey{}).(net.Conn)
	if m.poisoned(conn) {
		hijacked, _, hErr := w.(http.Hijacker).Hijack()
		util.FatalOnError("can't hijack connection: ", hErr)
		_ = hijacked.Close()

		return
	}

	m.callCount.Add(1)
	m.awaitBarrier()

	msg := new(dns.Msg)
	err = msg.Unpack(body)
	util.FatalOnError("can't deserialize message: ", err)

	response := m.answerFn(msg)
	response.SetReply(msg)

	raw, err := response.Pack()
	util.FatalOnError("can't serialize message: ", err)

	w.Header().Set("Content-Type", dnsContentType)

	_, err = w.Write(raw)
	util.FatalOnError("can't write response: ", err)
}

// Start starts the server and returns its upstream config.
func (m *MockDoHUpstreamServer) Start() config.Upstream {
	m.server = httptest.NewUnstartedServer(http.HandlerFunc(m.handle))

	// Explicitly HTTP/1.1: StartTLS then offers only http/1.1 over ALPN, so each
	// query needs its own connection. Under HTTP/2 one connection would multiplex
	// them all, and the connection-count assertions would no longer mean anything.
	m.server.EnableHTTP2 = false

	m.server.Config.ConnState = m.trackConn
	m.server.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, dohConnKey{}, c)
	}

	m.server.StartTLS()

	upstream, err := config.ParseUpstream(m.server.URL)
	util.FatalOnError("can't parse upstream: ", err)

	return upstream
}

func (m *MockDoHUpstreamServer) Close() {
	if m.server != nil {
		m.server.Close()
	}
}
