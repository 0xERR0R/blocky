package service

import (
	"fmt"
	"slices"
	"strings"

	"github.com/0xERR0R/blocky/util"
	"golang.org/x/exp/maps"
)

// Endpoint is a network endpoint on which to expose a service.
type Endpoint struct {
	// Protocol is the protocol to be exposed on this endpoint.
	Protocol string

	// AddrConf is the network address as configured by the user.
	AddrConf string
}

func EndpointsFromAddrs(proto string, addrs []string) []Endpoint {
	return util.ConvertEach(addrs, func(addr string) Endpoint {
		return Endpoint{
			Protocol: proto,
			AddrConf: addr,
		}
	})
}

func (e Endpoint) String() string {
	addr := e.AddrConf
	if strings.HasPrefix(addr, ":") {
		addr = "*" + addr
	}

	return fmt.Sprintf("%s://%s", e.Protocol, addr)
}

type endpointSet map[Endpoint]struct{}

func newEndpointSet(endpoints ...Endpoint) endpointSet {
	s := make(endpointSet, len(endpoints))

	for _, endpoint := range endpoints {
		s[endpoint] = struct{}{}
	}

	return s
}

func (s endpointSet) ToSlice() []Endpoint {
	return maps.Keys(s)
}

func (s endpointSet) IntersectSlice(others []Endpoint) {
	for endpoint := range s {
		if !slices.Contains(others, endpoint) {
			delete(s, endpoint)
		}
	}
}
