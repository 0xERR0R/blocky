package resolver

import (
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

type MockUDPUpstreamServer struct {
	callCount int32
	ln        *net.UDPConn
	answerFn  func(request *dns.Msg) (response *dns.Msg)
}

func NewMockUDPUpstreamServer() *MockUDPUpstreamServer {
	return &MockUDPUpstreamServer{}
}

func (t *MockUDPUpstreamServer) WithAnswerRR(answers ...string) *MockUDPUpstreamServer {
	t.answerFn = func(request *dns.Msg) (response *dns.Msg) {
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

func (t *MockUDPUpstreamServer) WithAnswerMsg(answer *dns.Msg) *MockUDPUpstreamServer {
	t.answerFn = func(request *dns.Msg) (response *dns.Msg) {
		return answer
	}

	return t
}

func (t *MockUDPUpstreamServer) WithAnswerError(errorCode int) *MockUDPUpstreamServer {
	t.answerFn = func(request *dns.Msg) (response *dns.Msg) {
		msg := new(dns.Msg)
		msg.Rcode = errorCode

		return msg
	}

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
	return int(atomic.LoadInt32(&t.callCount))
}

func (t *MockUDPUpstreamServer) Close() {
	if t.ln != nil {
		_ = t.ln.Close()
	}
}

func createConnection() *net.UDPConn {
	a, err := net.ResolveUDPAddr("udp4", ":0")
	util.FatalOnError("can't resolve address: ", err)

	ln, err := net.ListenUDP("udp4", a)
	util.FatalOnError("can't create connection: ", err)

	return ln
}

func (t *MockUDPUpstreamServer) Start() config.Upstream {
	ln := createConnection()

	ladr := ln.LocalAddr().String()
	host := strings.Split(ladr, ":")[0]
	p, err := config.ConvertPort(strings.Split(ladr, ":")[1])

	util.FatalOnError("can't convert port: ", err)

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
				msg := new(dns.Msg)
				err = msg.Unpack(buffer[0 : n-1])

				util.FatalOnError("can't deserialize message: ", err)

				response := t.answerFn(msg)

				atomic.AddInt32(&t.callCount, 1)
				// nil should indicate an error
				if response == nil {
					_, _ = ln.WriteToUDP([]byte("dummy"), addr)

					return
				}

				rCode := response.Rcode
				response.SetReply(msg)

				if rCode != 0 {
					response.Rcode = rCode
				}

				b, err := response.Pack()
				util.FatalOnError("can't serialize message: ", err)

				_, _ = ln.WriteToUDP(b, addr)
			}()
		}
	}()

	return config.Upstream{Net: config.NetProtocolTcpUdp, Host: host, Port: port}
}
