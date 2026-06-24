package resolver

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/miekg/dns"
	"github.com/onsi/ginkgo/v2"
)

type MockUDPUpstreamServer struct {
	callCount atomic.Int32
	ln        *net.UDPConn
	answerFn  func(request *dns.Msg) (response *dns.Msg)
}

func NewMockUDPUpstreamServer() *MockUDPUpstreamServer {
	srv := &MockUDPUpstreamServer{}

	ginkgo.DeferCleanup(srv.Close)

	return srv
}

func (t *MockUDPUpstreamServer) WithAnswerRR(answers ...string) *MockUDPUpstreamServer {
	t.answerFn = rrAnswerFn(answers...)

	return t
}

func (t *MockUDPUpstreamServer) WithAnswerMsg(answer *dns.Msg) *MockUDPUpstreamServer {
	t.answerFn = func(request *dns.Msg) (response *dns.Msg) {
		return answer
	}

	return t
}

func (t *MockUDPUpstreamServer) WithAnswerError(errorCode int) *MockUDPUpstreamServer {
	t.answerFn = errorAnswerFn(errorCode)

	return t
}

func (t *MockUDPUpstreamServer) WithAnswerFn(fn func(request *dns.Msg) (response *dns.Msg)) *MockUDPUpstreamServer {
	t.answerFn = fn

	return t
}

func (t *MockUDPUpstreamServer) WithDelay(delay time.Duration) *MockUDPUpstreamServer {
	answerFn := t.answerFn
	if answerFn == nil {
		panic("WithDelay must be called after a WithAnswer function")
	}

	t.answerFn = func(request *dns.Msg) *dns.Msg {
		time.Sleep(delay)

		return answerFn(request)
	}

	return t
}

func (t *MockUDPUpstreamServer) GetCallCount() int {
	return int(t.callCount.Load())
}

func (t *MockUDPUpstreamServer) ResetCallCount() {
	t.callCount.Store(0)
}

func (t *MockUDPUpstreamServer) Close() {
	if t.ln != nil {
		_ = t.ln.Close()
	}
}

func createConnection() *net.UDPConn {
	a, err := net.ResolveUDPAddr("udp4", ":0")
	if err != nil {
		panic(fmt.Sprintf("can't resolve address: %v", err))
	}

	ln, err := net.ListenUDP("udp4", a)
	if err != nil {
		panic(fmt.Sprintf("can't create connection: %v", err))
	}

	return ln
}

func (t *MockUDPUpstreamServer) Start() config.Upstream {
	ln := createConnection()

	ladr := ln.LocalAddr().String()
	host := strings.Split(ladr, ":")[0]
	p, err := config.ConvertPort(strings.Split(ladr, ":")[1])
	if err != nil {
		panic(fmt.Sprintf("can't convert port: %v", err))
	}

	port := p
	t.ln = ln

	go func() {
		const bufferSize = 1024

		for {
			buffer := make([]byte, bufferSize)

			n, addr, err := ln.ReadFromUDP(buffer)
			if err != nil {
				// closed
				break
			}

			go func() {
				defer ginkgo.GinkgoRecover()
				msg := new(dns.Msg)
				err = msg.Unpack(buffer[0:n])
				if err != nil {
					panic(fmt.Sprintf("can't deserialize message: %v", err))
				}

				response := t.answerFn(msg)

				t.callCount.Add(1)
				// nil should indicate an error
				if response == nil {
					_, _ = ln.WriteToUDP([]byte("dummy"), addr)

					return
				}

				b, err := mockReply(msg, response).Pack()
				if err != nil {
					panic(fmt.Sprintf("can't serialize message: %v", err))
				}

				_, _ = ln.WriteToUDP(b, addr)
			}()
		}
	}()

	return config.Upstream{Net: config.NetProtocolTcpUdp, Host: host, Port: port}
}
