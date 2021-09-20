package resolver

import (
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"

	"github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/mock"
)

type resolverMock struct {
	mock.Mock
	NextResolver
}

func (r *resolverMock) Configuration() (result []string) {
	return
}

func (r *resolverMock) Resolve(req *model.Request) (*model.Response, error) {
	args := r.Called(req)
	resp, ok := args.Get(0).(*model.Response)

	if ok {
		return resp, args.Error((1))
	}

	return nil, args.Error(1)
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

// TestUDPUpstream creates a mock UDP upstream
//nolint:funlen
func TestUDPUpstream(fn func(request *dns.Msg) (response *dns.Msg)) config.Upstream {
	a, err := net.ResolveUDPAddr("udp4", ":0")
	util.FatalOnError("can't resolve address: ", err)

	ln, err := net.ListenUDP("udp4", a)
	util.FatalOnError("can't create connection: ", err)

	ladr := ln.LocalAddr().String()
	host := strings.Split(ladr, ":")[0]
	p, err := strconv.ParseUint(strings.Split(ladr, ":")[1], 10, 16)

	util.FatalOnError("can't convert port: ", err)

	port := uint16(p)

	go func() {
		for {
			buffer := make([]byte, 1024)
			n, addr, err := ln.ReadFromUDP(buffer)
			util.FatalOnError("error on reading from udp: ", err)

			msg := new(dns.Msg)
			err = msg.Unpack(buffer[0 : n-1])

			util.FatalOnError("can't deserialize message: ", err)

			response := fn(msg)
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
			util.FatalOnError("can't write to UDP: ", err)
		}
	}()

	return config.Upstream{Net: config.NetProtocolTcpUdp, Host: host, Port: port}
}
