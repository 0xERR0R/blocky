package service

import (
	"errors"
	"net/http"
	"strings"

	"github.com/0xERR0R/blocky/util"
	"github.com/go-chi/chi/v5"
)

const (
	HTTPProtocol  = "http"
	HTTPSProtocol = "https"
)

// HTTPService is a Service using a HTTP router.
type HTTPService interface {
	Service
	Merger

	// Router returns the service's router.
	Router() chi.Router
}

// HTTPInfo can be embedded in structs to help implement HTTPService.
type HTTPInfo struct {
	Info

	Mux *chi.Mux
}

func (i *HTTPInfo) Router() chi.Router { return i.Mux }

// MergeHTTP merges two compatible HTTPServices.
//
// The second parameter is of type `Service` to make it easy to call
// from a `Merger.Merge` implementation.
func MergeHTTP(a HTTPService, b Service) (Merger, error) {
	return newHTTPMerger(a).Merge(b)
}

var _ HTTPService = (*httpMerger)(nil)

// httpMerger can merge HTTPServices by combining their routes.
type httpMerger struct {
	inner     []HTTPService
	router    chi.Router
	endpoints endpointSet
}

func newHTTPMerger(first HTTPService) *httpMerger {
	return &httpMerger{
		inner:     []HTTPService{first},
		router:    first.Router(),
		endpoints: newEndpointSet(first.ExposeOn()...),
	}
}

func (m *httpMerger) String() string { return svcString(m) }

func (m *httpMerger) ServiceName() string {
	names := util.ConvertEach(m.inner, func(svc HTTPService) string {
		return svc.ServiceName()
	})

	return strings.Join(names, " & ")
}

func (m *httpMerger) ExposeOn() []Endpoint { return m.endpoints.ToSlice() }
func (m *httpMerger) Router() chi.Router   { return m.router }

func (m *httpMerger) Merge(other Service) (Merger, error) {
	httpSvc, ok := other.(HTTPService)
	if !ok {
		return nil, errors.New("not an HTTPService")
	}

	type middleware = func(http.Handler) http.Handler

	// Can't do `.Mount("/", ...)` otherwise we can only merge at most once since / will already be defined
	_ = chi.Walk(httpSvc.Router(), func(method, route string, handler http.Handler, middlewares ...middleware) error {
		m.router.With(middlewares...).Method(method, route, handler)

		// Expose /example/ as /example too
		// Workaround for chi.Walk missing the second form https://github.com/go-chi/chi/issues/830
		// The main point of this is for DoH's `/dns-query` endpoint.
		if strings.HasSuffix(route, "/") {
			route := strings.TrimSuffix(route, "/")
			m.router.With(middlewares...).Method(method, route, handler)
		}

		return nil
	})

	m.inner = append(m.inner, httpSvc)

	// Don't expose any service more than it expects
	m.endpoints.IntersectSlice(other.ExposeOn())

	return m, nil
}
