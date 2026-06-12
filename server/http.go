package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/go-chi/chi/v5"
	"github.com/rs/cors"
)

type httpServer struct {
	inner http.Server

	name string
}

func newHTTPServer(name string, handler http.Handler, cfg *config.Config) *httpServer {
	var (
		writeTimeout      = cfg.Blocking.Loading.Downloads.WriteTimeout
		readTimeout       = cfg.Blocking.Loading.Downloads.ReadTimeout
		readHeaderTimeout = cfg.Blocking.Loading.Downloads.ReadHeaderTimeout
	)

	return &httpServer{
		inner: http.Server{
			ReadTimeout:       time.Duration(readTimeout),
			ReadHeaderTimeout: time.Duration(readHeaderTimeout),
			WriteTimeout:      time.Duration(writeTimeout),
			Handler:           withCommonMiddleware(handler),
		},

		name: name,
	}
}

func (s *httpServer) String() string {
	return s.name
}

func (s *httpServer) Serve(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()

		s.inner.Close()
	}()

	if err := s.inner.Serve(l); err != nil {
		return fmt.Errorf("HTTP server '%s' failed to serve: %w", s.name, err)
	}

	return nil
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
			w.Header().Set("Strict-Transport-Security", "max-age=63072000")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("x-xss-protection", "1; mode=block")
		}

		next.ServeHTTP(w, r)
	})
}

func newCORSMiddleware() httpMiddleware {
	const corsMaxAge = 5 * time.Minute

	options := cors.Options{
		AllowCredentials: true,
		// Allow all request headers: web UIs send tool-specific headers
		// (e.g. Grafana action buttons always add 'X-Grafana-Action') and a
		// disallowed header makes the preflight fail. The API attaches no
		// security semantics to request headers, and rs/cors answers a
		// wildcard by echoing the requested headers, which is spec-compliant
		// also for 'Authorization'.
		AllowedHeaders: []string{"*"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedOrigins: []string{"*"},
		// Allow Chromium's Private Network Access preflights, sent when a
		// public site addresses a private IP (e.g. a hosted Grafana
		// dashboard calling the blocky API on a LAN)
		AllowPrivateNetwork: true,
		ExposedHeaders:      []string{"Link"},
		MaxAge:              int(corsMaxAge.Seconds()),
	}

	return cors.New(options).Handler
}
