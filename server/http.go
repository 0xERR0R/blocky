// Modified by Chris Snell, 2026
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/cors"
)

type httpServer struct {
	inner http.Server

	name string
}

const (
	serverReadTimeout       = 30 * time.Second
	serverReadHeaderTimeout = 10 * time.Second
	serverWriteTimeout      = 60 * time.Second
)

func newHTTPServer(name string, handler http.Handler) *httpServer {
	return newBareHTTPServer(name, withCommonMiddleware(handler))
}

// newBareHTTPServer is newHTTPServer without the withCommonMiddleware layer, so
// the handler is served with no CORS policy and no TLS response headers.
//
// Only the loopback diagnostics listener uses this. Its CORS needs are not
// "same-origin" but "none at all": the same-origin policy mirrors the Origin
// header with Access-Control-Allow-Credentials whenever Origin's host matches
// the request Host, and under DNS rebinding a page controls *both* — which would
// make heap dumps readable by browser JavaScript. Everything reachable from the
// network goes through newHTTPServer.
func newBareHTTPServer(name string, handler http.Handler) *httpServer {
	return &httpServer{
		inner: http.Server{
			ReadTimeout:       serverReadTimeout,
			ReadHeaderTimeout: serverReadHeaderTimeout,
			WriteTimeout:      serverWriteTimeout,
			Handler:           handler,
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

	// ErrServerClosed is what Serve returns once Close or Shutdown has been
	// called, i.e. every clean stop. Reporting it as a failure would put an
	// error on the server's error channel on every shutdown.
	if err := s.inner.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP server '%s' failed to serve: %w", s.name, err)
	}

	return nil
}

// Close stops serving and releases the port.
//
// Shutdown alone is not enough: it closes only the listeners the server is
// actively serving, so one that was constructed but never started would keep
// its port bound. Callers need the port back by the time this returns — relying
// on the context-cancellation goroutine above is a race, because cancelling a
// context does not wait for the goroutine observing it.
func (s *httpServer) Close(ctx context.Context, l net.Listener) error {
	shutdownErr := s.inner.Shutdown(ctx)

	if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("HTTP server '%s': close listener %s failed: %w", s.name, l.Addr(), err)
	}

	if shutdownErr != nil {
		return fmt.Errorf("HTTP server '%s' shutdown failed: %w", s.name, shutdownErr)
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
		// Same-origin only: mirror the Origin header iff its host matches
		// the request Host. The SPA is served from the same origin as the
		// API, so no cross-origin credentialed fetches should ever be
		// legitimate. AllowedOrigins: ["*"] + AllowCredentials: true is
		// spec-invalid (browsers reject it), and a permissive
		// AllowOriginFunc defeats the CSRF defense provided by
		// SameSite=Lax + the X-Requested-With header check.
		//
		// rs/cors (upstream replaced go-chi/cors) splits the callback: its
		// AllowOriginFunc sees only the origin string, so same-origin — which
		// needs the request's Host — has to use the request-aware variant.
		// AllowOriginRequestFunc is the deprecated spelling of that. No extra
		// Vary header is declared: the decision varies on Host, but a shared
		// cache already keys on the effective request URI, so naming it would
		// add a header to every response for nothing.
		AllowOriginVaryRequestFunc: func(r *http.Request, origin string) (bool, []string) {
			return sameOriginFunc(r, origin), nil
		},
		AllowCredentials: true,
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		ExposedHeaders:   []string{"Link"},
		MaxAge:           int(corsMaxAge.Seconds()),
	}

	return cors.New(options).Handler
}

// sameOriginFunc returns true iff the Origin header's host matches the
// request Host. Returns false for empty/unparseable Origin values.
func sameOriginFunc(r *http.Request, origin string) bool {
	if origin == "" {
		return false
	}

	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}

	return strings.EqualFold(u.Host, r.Host)
}
