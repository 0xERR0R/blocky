package server

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/service"
	"github.com/0xERR0R/blocky/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
)

// httpMiscService implements service.HTTPService.
//
// This supports the existing single HTTP/HTTPS endpoints
// that expose everything. The goal is to split it up
// and remove it.
type httpMiscService struct {
	service.HTTPInfo
}

func newHTTPMiscService(cfg *config.Config, openAPIImpl api.StrictServerInterface) *httpMiscService {
	endpoints := util.ConcatSlices(
		service.EndpointsFromAddrs(service.HTTPProtocol, cfg.Ports.HTTP),
		service.EndpointsFromAddrs(service.HTTPSProtocol, cfg.Ports.HTTPS),
	)

	return &httpMiscService{
		HTTPInfo: service.HTTPInfo{
			Info: service.Info{
				Name:      "HTTP",
				Endpoints: endpoints,
			},

			Mux: createHTTPRouter(cfg, openAPIImpl),
		},
	}
}

func (s *httpMiscService) Merge(other service.Service) (service.Merger, error) {
	return service.MergeHTTP(s, other)
}

// httpServer implements subServer for HTTP.
type httpServer struct {
	service.HTTPService

	inner http.Server
}

func newHTTPServer(svc service.HTTPService) *httpServer {
	const (
		readHeaderTimeout = 20 * time.Second
		readTimeout       = 20 * time.Second
		writeTimeout      = 20 * time.Second
	)

	return &httpServer{
		HTTPService: svc,

		inner: http.Server{
			Handler:           withCommonMiddleware(svc.Router()),
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
		},
	}
}

func (s *httpServer) Serve(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()

		s.inner.Close()
	}()

	return s.inner.Serve(l)
}

func withCommonMiddleware(inner http.Handler) *chi.Mux {
	// Middleware must be defined before routes, so
	// create a new router and mount the inner handler
	mux := chi.NewMux()

	mux.Use(
		secureHeadersMiddleware,
		newCORSMiddleware(),
	)

	mux.Mount("/", inner)

	return mux
}

type httpMiddleware = func(http.Handler) http.Handler

func secureHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w.Header().Set("strict-transport-security", "max-age=63072000")
			w.Header().Set("x-frame-options", "DENY")
			w.Header().Set("x-content-type-options", "nosniff")
			w.Header().Set("x-xss-protection", "1; mode=block")
		}

		next.ServeHTTP(w, r)
	})
}

func newCORSMiddleware() httpMiddleware {
	const corsMaxAge = 5 * time.Minute

	options := cors.Options{
		AllowCredentials: true,
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedOrigins:   []string{"*"},
		ExposedHeaders:   []string{"Link"},
		MaxAge:           int(corsMaxAge.Seconds()),
	}

	return cors.New(options).Handler
}
