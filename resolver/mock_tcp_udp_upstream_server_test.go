package resolver

import (
	"fmt"
	"net"
	"sync/atomic"

	"github.com/0xERR0R/blocky/config"
	"github.com/miekg/dns"
	"github.com/onsi/ginkgo/v2"
)

// answerFn builds the response for a received query. The mock fixes the response ID and the
// response bit afterwards, so a handler is free to return a mismatched question section or set the
// TC bit to exercise blocky's fallback logic.
type answerFn func(request *dns.Msg) *dns.Msg

// mockTCPUDPUpstreamServer is a test upstream that listens on a single address over BOTH UDP and
// TCP, with independent handlers and per-protocol call counters. Unlike MockUDPUpstreamServer (UDP
// only) it lets a test assert which transport blocky actually used — e.g. that TCP is never dialed
// when the UDP answer is already clean.
type mockTCPUDPUpstreamServer struct {
	udpAnswer answerFn
	tcpAnswer answerFn
	udpCount  atomic.Int32
	tcpCount  atomic.Int32
	udpSrv    *dns.Server
	tcpSrv    *dns.Server
}

func newMockTCPUDPUpstreamServer(udpAnswer, tcpAnswer answerFn) *mockTCPUDPUpstreamServer {
	srv := &mockTCPUDPUpstreamServer{udpAnswer: udpAnswer, tcpAnswer: tcpAnswer}

	ginkgo.DeferCleanup(srv.Close)

	return srv
}

func (m *mockTCPUDPUpstreamServer) UDPCallCount() int { return int(m.udpCount.Load()) }
func (m *mockTCPUDPUpstreamServer) TCPCallCount() int { return int(m.tcpCount.Load()) }

func (m *mockTCPUDPUpstreamServer) Close() {
	if m.udpSrv != nil {
		_ = m.udpSrv.Shutdown()
	}

	if m.tcpSrv != nil {
		_ = m.tcpSrv.Shutdown()
	}
}

func (m *mockTCPUDPUpstreamServer) handler(counter *atomic.Int32, answer answerFn) dns.HandlerFunc {
	return func(w dns.ResponseWriter, request *dns.Msg) {
		defer ginkgo.GinkgoRecover()

		counter.Add(1)

		resp := answer(request)
		if resp == nil {
			// nil simulates a broken upstream, like in MockUDPUpstreamServer: answer with
			// garbage the client can't parse
			_, _ = w.Write([]byte("dummy"))

			return
		}

		resp.Id = request.Id
		resp.Response = true

		_ = w.WriteMsg(resp)
	}
}

func (m *mockTCPUDPUpstreamServer) Start() config.Upstream {
	return m.start(true, true)
}

// StartTCPOnly is Start with the UDP socket closed again after claiming the port: UDP queries are
// refused, simulating an upstream reachable only over TCP (e.g. UDP blocked by a firewall).
func (m *mockTCPUDPUpstreamServer) StartTCPOnly() config.Upstream {
	return m.start(false, true)
}

// StartUDPOnly is Start with the TCP listener closed again after claiming the port: TCP connections
// are refused, simulating an upstream whose TCP fallback is unavailable.
func (m *mockTCPUDPUpstreamServer) StartUDPOnly() config.Upstream {
	return m.start(true, false)
}

// start always binds both sockets so the port is guaranteed to belong to this mock on both
// protocols, then closes the ones not asked for so queries over them are refused immediately.
func (m *mockTCPUDPUpstreamServer) start(udp, tcp bool) config.Upstream {
	ip := net.ParseIP("127.0.0.1")

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
	if err != nil {
		panic(fmt.Sprintf("can't create UDP connection: %v", err))
	}

	port := udpConn.LocalAddr().(*net.UDPAddr).Port

	tcpLn, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: ip, Port: port})
	if err != nil {
		panic(fmt.Sprintf("can't create TCP listener: %v", err))
	}

	if udp {
		m.udpSrv = &dns.Server{PacketConn: udpConn, Handler: m.handler(&m.udpCount, m.udpAnswer)}

		go func() {
			defer ginkgo.GinkgoRecover()
			_ = m.udpSrv.ActivateAndServe()
		}()
	} else {
		_ = udpConn.Close()
	}

	if tcp {
		m.tcpSrv = &dns.Server{Listener: tcpLn, Handler: m.handler(&m.tcpCount, m.tcpAnswer)}

		go func() {
			defer ginkgo.GinkgoRecover()
			_ = m.tcpSrv.ActivateAndServe()
		}()
	} else {
		_ = tcpLn.Close()
	}

	return config.Upstream{Net: config.NetProtocolTcpUdp, Host: ip.String(), Port: uint16(port)}
}
