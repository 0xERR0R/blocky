package resolver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync/atomic"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/onsi/ginkgo/v2"
	"github.com/quic-go/quic-go"
)

// MockDoQUpstreamServer is a mock DNS-over-QUIC server for testing.
type MockDoQUpstreamServer struct {
	callCount int32
	connCount int32
	listener  *quic.Listener
	transport *quic.Transport
	udpConn   *net.UDPConn
	answerFn  func(request *dns.Msg) (response *dns.Msg)
}

func NewMockDoQUpstreamServer() *MockDoQUpstreamServer {
	srv := &MockDoQUpstreamServer{}
	ginkgo.DeferCleanup(srv.Close)

	return srv
}

func (t *MockDoQUpstreamServer) WithAnswerRR(answers ...string) *MockDoQUpstreamServer {
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

func (t *MockDoQUpstreamServer) WithAnswerError(errorCode int) *MockDoQUpstreamServer {
	t.answerFn = func(_ *dns.Msg) *dns.Msg {
		msg := new(dns.Msg)
		msg.Rcode = errorCode

		return msg
	}

	return t
}

func (t *MockDoQUpstreamServer) GetCallCount() int {
	return int(atomic.LoadInt32(&t.callCount))
}

// GetConnCount returns the number of QUIC connections accepted by the server.
func (t *MockDoQUpstreamServer) GetConnCount() int {
	return int(atomic.LoadInt32(&t.connCount))
}

func (t *MockDoQUpstreamServer) Close() {
	if t.listener != nil {
		_ = t.listener.Close()
	}

	if t.transport != nil {
		_ = t.transport.Close()
	}

	if t.udpConn != nil {
		_ = t.udpConn.Close()
	}
}

func generateSelfSignedCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	util.FatalOnError("can't generate key", err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	util.FatalOnError("can't create certificate", err)

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

func (t *MockDoQUpstreamServer) Start() config.Upstream {
	cert := generateSelfSignedCert()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq"},
	}

	udpAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	util.FatalOnError("can't resolve address", err)

	udpConn, err := net.ListenUDP("udp4", udpAddr)
	util.FatalOnError("can't create UDP socket", err)

	t.udpConn = udpConn

	tr := &quic.Transport{Conn: udpConn}
	t.transport = tr

	listener, err := tr.Listen(tlsConfig, &quic.Config{})
	util.FatalOnError("can't create QUIC listener", err)

	t.listener = listener

	go t.serve()

	addr := udpConn.LocalAddr().(*net.UDPAddr)
	port, err := config.ConvertPort(strconv.Itoa(addr.Port))
	util.FatalOnError("can't convert port", err)

	return config.Upstream{Net: config.NetProtocolQuic, Host: "127.0.0.1", Port: port}
}

func (t *MockDoQUpstreamServer) serve() {
	for {
		conn, err := t.listener.Accept(context.Background())
		if err != nil {
			return
		}

		atomic.AddInt32(&t.connCount, 1)

		go t.handleConn(conn)
	}
}

func (t *MockDoQUpstreamServer) handleConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		go func() {
			defer ginkgo.GinkgoRecover()
			t.handleStream(stream)
		}()
	}
}

func (t *MockDoQUpstreamServer) handleStream(stream *quic.Stream) {
	defer stream.Close()

	data, err := io.ReadAll(stream)
	if err != nil || len(data) < 2 {
		return
	}

	msgLen := binary.BigEndian.Uint16(data[:2])
	if int(msgLen) != len(data)-2 {
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(data[2:]); err != nil {
		return
	}

	atomic.AddInt32(&t.callCount, 1)

	response := t.answerFn(msg)
	rCode := response.Rcode
	response.SetReply(msg)

	if rCode != 0 {
		response.Rcode = rCode
	}

	packed, err := response.Pack()
	util.FatalOnError("can't serialize message", err)

	buf := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(buf, uint16(len(packed)))
	copy(buf[2:], packed)

	_, _ = stream.Write(buf)
}
