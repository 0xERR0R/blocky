// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/0xERR0R/blocky/config"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// debugServerName is the label the diagnostics listener logs under.
const debugServerName = "http-debug"

// newDebugRouter returns the router for the diagnostics listener: chi's pprof
// subrouter — which also serves expvar at /debug/vars — mounted at /debug, so
// the absolute paths net/http/pprof's own index page emits keep resolving.
//
// There is no auth middleware on this router by design. The listener binds
// loopback only, so reaching it already requires local access, and a session
// cookie in front of it would break `go tool pprof` for no gain.
func newDebugRouter() *chi.Mux {
	router := chi.NewRouter()
	router.Mount("/debug", middleware.Profiler())

	return router
}

// newDebugHTTPServer is newHTTPServer with the write timeout lifted.
// /debug/pprof/profile and /debug/pprof/trace stream for as long as the caller
// asks — `go tool pprof -seconds=120` — and serverWriteTimeout would cut that
// off mid-profile. Acceptable here and only here, because the listener is
// loopback-only, so an idle response cannot be held open from the network.
func newDebugHTTPServer(handler http.Handler) *httpServer {
	srv := newHTTPServer(debugServerName, handler)
	srv.inner.WriteTimeout = 0

	return srv
}

// createDebugListeners binds the diagnostics listener on loopback, one listener
// per IP family.
//
// Only one of the two has to succeed: a host with IPv6 disabled cannot bind
// [::1] and an IPv6-only one cannot bind 127.0.0.1, and neither should stop the
// server from starting. Failing on every address is an error — the operator
// asked for this listener, and silently not having it is worse than not
// starting.
func createDebugListeners(ctx context.Context, cfg *config.Debug) ([]net.Listener, error) {
	addresses := cfg.ListenAddresses()

	listeners := make([]net.Listener, 0, len(addresses))
	lc := &net.ListenConfig{}

	var errs []error

	for _, address := range addresses {
		listener, err := lc.Listen(ctx, networkTCP, address)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		listeners = append(listeners, listener)
	}

	if len(listeners) == 0 {
		return nil, fmt.Errorf("start debug listener on %s failed: %w",
			strings.Join(addresses, ", "), errors.Join(errs...))
	}

	for _, err := range errs {
		logger().Warnf("debug listener: %v; continuing on the address that did bind", err)
	}

	return listeners, nil
}

// addDebugListeners opens the loopback diagnostics listener and registers it in
// the server's listener set, so Start serves it and Stop releases the port like
// any other HTTP listener. A no-op unless debug.enable is set.
//
// Diagnostics get their own listener rather than a route group on the HTTP API
// port: RequireAuth passes through every path that is not /api/* so the SPA
// shell can render, which made /debug mounted there readable without a session
// no matter which guards the route golden listed (GRA-647).
func (s *Server) addDebugListeners(ctx context.Context, cfg *config.Config) error {
	if !cfg.Debug.IsEnabled() {
		return nil
	}

	listeners, err := createDebugListeners(ctx, &cfg.Debug)
	if err != nil {
		return err
	}

	srv := newDebugHTTPServer(newDebugRouter())
	for _, l := range listeners {
		s.servers[l] = srv
	}

	return nil
}
