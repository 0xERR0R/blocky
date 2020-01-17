package resolver

import (
	"blocky/config"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

type resolverMock struct {
	mock.Mock
	NextResolver
}

func (r *resolverMock) Configuration() (result []string) {
	return
}

func (r *resolverMock) Resolve(req *Request) (*Response, error) {
	args := r.Called(req)
	return args.Get(0).(*Response), args.Error(1)
}

func TestUDPUpstream(fn func(request *dns.Msg) (response *dns.Msg)) config.Upstream {
	a, err := net.ResolveUDPAddr("udp4", ":0")
	if err != nil {
		log.Fatal("can't resolve address: ", err)
	}

	ln, err := net.ListenUDP("udp4", a)
	if err != nil {
		log.Fatal("can't create connection: ", err)
	}

	ladr := ln.LocalAddr().String()
	host := strings.Split(ladr, ":")[0]
	p, err := strconv.Atoi(strings.Split(ladr, ":")[1])

	if err != nil {
		log.Fatal("can't convert port: ", err)
	}

	port := uint16(p)

	go func() {
		for {
			buffer := make([]byte, 1024)
			n, addr, err := ln.ReadFromUDP(buffer)

			if err != nil {
				log.Fatal("error on reading from udp: ", err)
			}

			msg := new(dns.Msg)
			err = msg.Unpack(buffer[0 : n-1])

			if err != nil {
				log.Fatal("can't deserialize message: ", err)
			}

			response := fn(msg)
			response.SetReply(msg)

			b, err := response.Pack()
			if err != nil {
				log.Fatal("can't serialize message: ", err)
			}

			_, err = ln.WriteToUDP(b, addr)
			if err != nil {
				log.Fatal("can't write to UDP: ", err)
			}
		}
	}()

	return config.Upstream{Net: "udp", Host: host, Port: port}
}
