package resolver

import (
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"

	"github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/mock"
)

type MockResolver struct {
	mock.Mock
	NextResolver

	ResolveFn  func(req *model.Request) (*model.Response, error)
	ResponseFn func(req *dns.Msg) *dns.Msg
	AnswerFn   func(t uint16, qName string) *dns.Msg
}

func (r *MockResolver) Configuration() []string {
	args := r.Called()

	return args.Get(0).([]string)
}

func (r *MockResolver) Resolve(req *model.Request) (*model.Response, error) {
	args := r.Called(req)

	if r.ResolveFn != nil {
		return r.ResolveFn(req)
	}

	if r.ResponseFn != nil {
		return &model.Response{
			Res:    r.ResponseFn(req.Req),
			Reason: "",
			RType:  model.ResponseTypeRESOLVED,
		}, nil
	}

	if r.AnswerFn != nil {
		for _, question := range req.Req.Question {
			answer := r.AnswerFn(question.Qtype, question.Name)
			if answer != nil {
				return &model.Response{
					Res:    answer,
					Reason: "",
					RType:  model.ResponseTypeRESOLVED,
				}, nil
			}
		}

		response := new(dns.Msg)
		response.SetRcode(req.Req, dns.RcodeBadName)

		return &model.Response{
			Res:    response,
			Reason: "",
			RType:  model.ResponseTypeRESOLVED,
		}, nil
	}

	resp, ok := args.Get(0).(*model.Response)

	if ok {
		return resp, args.Error(1)
	}

	return nil, args.Error(1)
}

// TestBootstrap creates a mock Bootstrap
func TestBootstrap(response *dns.Msg) *Bootstrap {
	bootstrapUpstream := &MockResolver{}

	b, err := NewBootstrap(&config.Config{})
	util.FatalOnError("can't create bootstrap", err)

	b.resolver = bootstrapUpstream
	b.upstream = bootstrapUpstream

	if response != nil {
		bootstrapUpstream.
			On("Resolve", mock.Anything).
			Return(&model.Response{Res: response}, nil)
	}

	return b
}

// TestDOHUpstream creates a mock DoH Upstream
func TestDOHUpstream(fn func(request *dns.Msg) (response *dns.Msg),
	reqFn ...func(w http.ResponseWriter)) config.Upstream {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)

		util.FatalOnError("can't read request: ", err)

		msg := new(dns.Msg)
		err = msg.Unpack(body)
		util.FatalOnError("can't deserialize message: ", err)

		response := fn(msg)
		response.SetReply(msg)

		b, err := response.Pack()

		util.FatalOnError("can't serialize message: ", err)

		w.Header().Set("content-type", "application/dns-message")

		for _, f := range reqFn {
			if f != nil {
				f(w)
			}
		}
		_, err = w.Write(b)

		util.FatalOnError("can't write response: ", err)
	}))
	upstream, err := config.ParseUpstream(server.URL)

	util.FatalOnError("can't resolve address: ", err)

	return upstream
}

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

func (t *MockUDPUpstreamServer) GetCallCount() int {
	return int(atomic.LoadInt32(&t.callCount))
}

func (t *MockUDPUpstreamServer) Close() {
	if t.ln != nil {
		_ = t.ln.Close()
	}
}

func CreateConnection() *net.UDPConn {
	a, err := net.ResolveUDPAddr("udp4", ":0")
	util.FatalOnError("can't resolve address: ", err)

	ln, err := net.ListenUDP("udp4", a)
	util.FatalOnError("can't create connection: ", err)

	return ln
}

func (t *MockUDPUpstreamServer) Start() config.Upstream {
	ln := CreateConnection()

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

			msg := new(dns.Msg)
			err = msg.Unpack(buffer[0 : n-1])

			util.FatalOnError("can't deserialize message: ", err)

			var response = t.answerFn(msg)

			atomic.AddInt32(&t.callCount, 1)
			// nil should indicate an error
			if response == nil {
				_, _ = ln.WriteToUDP([]byte("dummy"), addr)

				continue
			}

			rCode := response.Rcode
			response.SetReply(msg)

			if rCode != 0 {
				response.Rcode = rCode
			}

			b, err := response.Pack()
			util.FatalOnError("can't serialize message: ", err)

			_, err = ln.WriteToUDP(b, addr)
			if err != nil {
				// closed
				break
			}
		}
	}()

	return config.Upstream{Net: config.NetProtocolTcpUdp, Host: host, Port: port}
}
