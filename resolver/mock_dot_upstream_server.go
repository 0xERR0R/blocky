package resolver

import (
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/onsi/ginkgo/v2"
)

// MockDoTUpstreamServer is a mock DNS-over-TLS (tcp-tls) server for testing the
// connection pool. It counts accepted connections (to prove reuse) and served
// queries, and can close connections after a fixed number of queries to
// simulate an upstream that drops idle connections. With WithReplyDelay it
// answers pipelined queries concurrently, so replies can arrive out of order.
type MockDoTUpstreamServer struct {
	callCount  atomic.Int32
	connCount  atomic.Int32
	openConns  atomic.Int32
	closeAfter atomic.Int32
	hangUp     atomic.Bool

	listener   net.Listener
	answerFn   func(request *dns.Msg) (response *dns.Msg)
	replyDelay func(request *dns.Msg) time.Duration

	// mu guards conns, the set of accepted connections Close must tear down so
	// their handleConn goroutines don't block forever on ReadMsg.
	mu     sync.Mutex
	conns  []net.Conn
	closed chan struct{}
	once   sync.Once
}

func NewMockDoTUpstreamServer() *MockDoTUpstreamServer {
	srv := &MockDoTUpstreamServer{closed: make(chan struct{})}
	ginkgo.DeferCleanup(srv.Close)

	return srv
}

// WithReplyDelay answers each query in its own goroutine after delay(query), so
// a connection's replies can arrive in a different order than its queries.
// WithCloseAfter has no effect in this mode.
func (t *MockDoTUpstreamServer) WithReplyDelay(delay func(request *dns.Msg) time.Duration) *MockDoTUpstreamServer {
	t.replyDelay = delay

	return t
}

func (t *MockDoTUpstreamServer) WithAnswerRR(answers ...string) *MockDoTUpstreamServer {
	t.answerFn = rrAnswerFn(answers...)

	return t
}

func (t *MockDoTUpstreamServer) WithAnswerError(errorCode int) *MockDoTUpstreamServer {
	t.answerFn = errorAnswerFn(errorCode)

	return t
}

// WithHangUpOnFirstQuery makes the server close the connection the first query
// arrives on, without answering it.
func (t *MockDoTUpstreamServer) WithHangUpOnFirstQuery() *MockDoTUpstreamServer {
	t.hangUp.Store(true)

	return t
}

// WithCloseAfter makes the server close each connection after serving n queries,
// simulating an upstream that drops idle/old connections.
func (t *MockDoTUpstreamServer) WithCloseAfter(n int) *MockDoTUpstreamServer {
	t.closeAfter.Store(int32(n)) //nolint:gosec // small test value

	return t
}

func (t *MockDoTUpstreamServer) GetCallCount() int {
	return int(t.callCount.Load())
}

// GetConnCount returns the number of TLS connections accepted by the server.
func (t *MockDoTUpstreamServer) GetConnCount() int {
	return int(t.connCount.Load())
}

// openConnCount returns the number of accepted connections currently being
// served by a handleConn goroutine.
func (t *MockDoTUpstreamServer) openConnCount() int {
	return int(t.openConns.Load())
}

func (t *MockDoTUpstreamServer) Close() {
	t.once.Do(func() { close(t.closed) })

	if t.listener != nil {
		_ = t.listener.Close()
	}

	// Closing the listener does not close already-accepted connections, so close
	// them explicitly; otherwise their handleConn goroutines block on ReadMsg
	// forever (a goroutine + fd leak across the test suite).
	t.mu.Lock()
	conns := t.conns
	t.conns = nil
	t.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (t *MockDoTUpstreamServer) Start() config.Upstream {
	if t.answerFn == nil {
		panic("MockDoTUpstreamServer: configure an answer with WithAnswerRR or WithAnswerError before Start")
	}

	cert := generateSelfSignedCert()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	util.FatalOnError("can't create TLS listener", err)

	t.listener = listener

	go t.serve()

	addr := listener.Addr().(*net.TCPAddr) //nolint:forcetypeassert // tcp listener always yields *net.TCPAddr
	port, err := config.ConvertPort(strconv.Itoa(addr.Port))
	util.FatalOnError("can't convert port", err)

	return config.Upstream{Net: config.NetProtocolTcpTls, Host: loopbackIPv4Str, Port: port}
}

func (t *MockDoTUpstreamServer) serve() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return
		}

		t.connCount.Add(1)

		t.mu.Lock()
		t.conns = append(t.conns, conn)
		t.mu.Unlock()

		go t.handleConn(conn)
	}
}

func (t *MockDoTUpstreamServer) handleConn(conn net.Conn) {
	defer ginkgo.GinkgoRecover()
	defer func() { _ = conn.Close() }()

	t.openConns.Add(1)
	defer t.openConns.Add(-1)

	dnsConn := &dns.Conn{Conn: conn}

	var (
		served  int32
		writeMu sync.Mutex
	)

	for {
		msg, err := dnsConn.ReadMsg()
		if err != nil {
			return
		}

		t.callCount.Add(1)

		if t.hangUp.CompareAndSwap(true, false) {
			return
		}

		if t.replyDelay != nil {
			go t.replyLater(dnsConn, &writeMu, msg)

			continue
		}

		response := mockReply(msg, t.answerFn(msg))

		if err := dnsConn.WriteMsg(response); err != nil {
			return
		}

		served++
		if closeAfter := t.closeAfter.Load(); closeAfter > 0 && served >= closeAfter {
			return
		}
	}
}

// replyLater answers msg after its delay, unless the server is closed first.
func (t *MockDoTUpstreamServer) replyLater(dnsConn *dns.Conn, writeMu *sync.Mutex, msg *dns.Msg) {
	defer ginkgo.GinkgoRecover()

	select {
	case <-time.After(t.replyDelay(msg)):
	case <-t.closed:
		return
	}

	writeMu.Lock()
	defer writeMu.Unlock()

	_ = dnsConn.WriteMsg(mockReply(msg, t.answerFn(msg)))
}
