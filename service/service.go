// Package service exposes types to abstract services from the networking.
//
// The idea is that we build a set of services and a set of network endpoints (Listener).
// The services are then assigned to endpoints based on the address(es) they were configured for.
//
// Actual service to endpoint binding is not handled by the abstractions in this package as it is
// protocol specific.
// The general pattern is to make a "server" that wraps a service, and can then be started on an
// endpoint using a `Serve` method, similar to `http.Server`.
//
// To support exposing multiple compatible services on a single endpoint (example: DoH + metrics on a single port),
// services can implement `Merger`.
package service

import (
	"fmt"
	"slices"
	"strings"

	"github.com/0xERR0R/blocky/util"
)

// Service is a network exposed service.
//
// It contains only the logic and user configured addresses it should be exposed on.
// Is is meant to be associated to one or more sockets via those addresses.
// Actual association with a socket is protocol specific.
type Service interface {
	fmt.Stringer

	// ServiceName returns the user friendly name of the service.
	ServiceName() string

	// ExposeOn returns the set of endpoints the service should be exposed on.
	//
	// They can be used to find listener(s) with matching configuration.
	ExposeOn() []Endpoint
}

func svcString(s Service) string {
	endpoints := util.ConvertEach(s.ExposeOn(), func(e Endpoint) string { return e.String() })

	return fmt.Sprintf("%s on %s", s.ServiceName(), strings.Join(endpoints, ", "))
}

// Info can be embedded in structs to help implement Service.
type Info struct {
	name      string
	endpoints []Endpoint
}

func NewInfo(name string, endpoints []Endpoint) Info {
	return Info{
		name:      name,
		endpoints: endpoints,
	}
}

func (i *Info) ServiceName() string  { return i.name }
func (i *Info) ExposeOn() []Endpoint { return i.endpoints }
func (i *Info) String() string       { return svcString(i) }

// GroupByListener returns a map of listener and services grouped by configured address.
//
// Each input listener is a key in the map. The corresponding value is a service
// merged from all services with a matching address.
func GroupByListener(services []Service, listeners []Listener) (map[Listener]Service, error) {
	res := make(map[Listener]Service, len(listeners))
	unused := slices.Clone(services)

	for _, listener := range listeners {
		services := findAllCompatible(services, listener.Exposes())
		if len(services) == 0 {
			return nil, fmt.Errorf("found no compatible services for listener %s", listener)
		}

		svc, err := MergeAll(services...)
		if err != nil {
			return nil, fmt.Errorf("cannot merge services configured for listener %s: %w", listener, err)
		}

		res[listener] = svc

		// Algorithmic complexity is quite high here, but we don't care about performance here, at least for now
		for _, svc := range services {
			if i := slices.Index(unused, svc); i != -1 {
				unused = slices.Delete(unused, i, i+1)
			}
		}
	}

	if len(unused) != 0 {
		return nil, fmt.Errorf("found no compatible listener for services: %v", unused)
	}

	return res, nil
}

// findAllCompatible returns the subset of services that use the given Listener.
func findAllCompatible(services []Service, endpoint Endpoint) []Service {
	res := make([]Service, 0, len(services))

	for _, svc := range services {
		if isExposedOn(svc, endpoint) {
			res = append(res, svc)
		}
	}

	return res
}

func isExposedOn(svc Service, endpoint Endpoint) bool {
	return slices.Index(svc.ExposeOn(), endpoint) != -1
}
