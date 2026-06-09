package resolver

import (
	"crypto/tls"
	"net"
	"strconv"
	"sync/atomic"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/onsi/ginkgo/v2"
)

// MockDoTUpstreamServer is a mock DNS-over-TLS (tcp-tls) server for testing the
// connection pool. It counts accepted connections (to prove reuse) and served
// queries, and can close connections after a fixed number of queries to
// simulate an upstream that drops idle connections.
type MockDoTUpstreamServer struct {
	callCount  atomic.Int32
	connCount  atomic.Int32
	closeAfter int32

	listener net.Listener
	answerFn func(request *dns.Msg) (response *dns.Msg)
}

func NewMockDoTUpstreamServer() *MockDoTUpstreamServer {
	srv := &MockDoTUpstreamServer{}
	ginkgo.DeferCleanup(srv.Close)

	return srv
}

func (t *MockDoTUpstreamServer) WithAnswerRR(answers ...string) *MockDoTUpstreamServer {
	t.answerFn = func(_ *dns.Msg) *dns.Msg {
		msg := new(dns.Msg)

		for _, a := range answers {
			rr, err := dns.NewRR(a)
			util.FatalOnError("can't create RR", err)

			msg.Answer = append(msg.Answer, rr)
		}

		return msg
	}

	return t
}

func (t *MockDoTUpstreamServer) WithAnswerError(errorCode int) *MockDoTUpstreamServer {
	t.answerFn = func(_ *dns.Msg) *dns.Msg {
		msg := new(dns.Msg)
		msg.Rcode = errorCode

		return msg
	}

	return t
}

// WithCloseAfter makes the server close each connection after serving n queries,
// simulating an upstream that drops idle/old connections.
func (t *MockDoTUpstreamServer) WithCloseAfter(n int) *MockDoTUpstreamServer {
	t.closeAfter = int32(n) //nolint:gosec // small test value

	return t
}

func (t *MockDoTUpstreamServer) GetCallCount() int {
	return int(t.callCount.Load())
}

// GetConnCount returns the number of TLS connections accepted by the server.
func (t *MockDoTUpstreamServer) GetConnCount() int {
	return int(t.connCount.Load())
}

func (t *MockDoTUpstreamServer) Close() {
	if t.listener != nil {
		_ = t.listener.Close()
	}
}

func (t *MockDoTUpstreamServer) Start() config.Upstream {
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

		go t.handleConn(conn)
	}
}

func (t *MockDoTUpstreamServer) handleConn(conn net.Conn) {
	defer ginkgo.GinkgoRecover()
	defer func() { _ = conn.Close() }()

	dnsConn := &dns.Conn{Conn: conn}

	var served int32

	for {
		msg, err := dnsConn.ReadMsg()
		if err != nil {
			return
		}

		t.callCount.Add(1)

		response := t.answerFn(msg)
		rCode := response.Rcode
		response.SetReply(msg)

		if rCode != 0 {
			response.Rcode = rCode
		}

		if err := dnsConn.WriteMsg(response); err != nil {
			return
		}

		served++
		if t.closeAfter > 0 && served >= t.closeAfter {
			return
		}
	}
}
