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
// There is no session check on this router by design: the listener binds
// loopback only, so reaching it already requires local access, and a cookie in
// front of it would break `go tool pprof`. requireLoopbackHost is what stands in
// for that — see its comment for the attack it closes.
func newDebugRouter() *chi.Mux {
	router := chi.NewRouter()
	router.Use(requireLoopbackHost)
	router.Mount("/debug", middleware.Profiler())

	return router
}

// requireLoopbackHost rejects any request whose Host header does not name a
// loopback address or `localhost`.
//
// Binding loopback stops packets from off-box, but it does not stop a *browser*
// on the box: a page at attacker.example:6060 whose DNS rebinds to 127.0.0.1
// reaches this listener with a Host of its own choosing, and the response is
// then readable if any CORS policy accepts that origin. The debug server is
// built with newBareHTTPServer precisely so no such policy exists — this check
// is the second half, and it also covers the requests that need no CORS to do
// damage, like a drive-by `GET /debug/pprof/profile?seconds=100000`.
//
// The hosts every legitimate caller sends pass: `go tool pprof
// http://127.0.0.1:6060/...` directly, and `localhost:6060` or `127.0.0.1:6060`
// through an SSH tunnel or `kubectl port-forward`.
func requireLoopbackHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) {
			http.Error(w, "debug endpoints accept loopback Host headers only",
				http.StatusMisdirectedRequest)

			return
		}

		next.ServeHTTP(w, r)
	})
}

// isLoopbackHost reports whether a Host header names loopback. It accepts
// `localhost` by name and any address in 127.0.0.0/8 or ::1/128, with or without
// a port, so a caller is not forced to spell 127.0.0.1 when 127.0.0.2 is what
// their tunnel bound.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}

	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	hostname = strings.Trim(hostname, "[]")

	if strings.EqualFold(hostname, "localhost") {
		return true
	}

	ip := net.ParseIP(hostname)

	return ip != nil && ip.IsLoopback()
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

	srv := newBareHTTPServer(debugServerName, newDebugRouter())
	for _, l := range listeners {
		s.servers[l] = srv
	}

	return nil
}

// createDebugListeners binds the diagnostics listener on loopback, one listener
// per IP family.
//
// A host that simply lacks one of the two families is normal and must not stop
// the server from starting, so that failure alone is tolerated with a warning.
// Everything else — most usefully "address already in use", meaning a second
// instance or another process on this port — is fatal: reporting a port conflict
// as a warning would leave the listener half-present, on one family and not the
// other, which is the state the operator is least likely to notice.
func createDebugListeners(ctx context.Context, cfg *config.Debug) ([]net.Listener, error) {
	addresses := cfg.ListenAddresses()

	listeners := make([]net.Listener, 0, len(addresses))
	lc := &net.ListenConfig{}

	var absent []error

	for _, address := range addresses {
		listener, err := lc.Listen(ctx, networkTCP, address)

		switch {
		case err == nil:
			listeners = append(listeners, listener)
		case !familyAvailable(ctx, lc, address):
			absent = append(absent, err)
		default:
			closeAll(listeners)

			return nil, fmt.Errorf("start debug listener on %s failed: %w", address, err)
		}
	}

	if len(listeners) == 0 {
		return nil, fmt.Errorf("start debug listener on %s failed: %w",
			strings.Join(addresses, ", "), errors.Join(absent...))
	}

	for _, err := range absent {
		logger().Warnf("debug listener: %v; continuing on the address that did bind", err)
	}

	return listeners, nil
}

// familyAvailable reports whether the host can bind this address at all, by
// retrying it on port 0.
//
// This is how "no IPv6 on this host" is told apart from "that port is taken"
// without a per-platform errno table — the codes differ between unix and
// Windows, and syscall exports no WSAE* names to compare against. If the address
// binds once the OS picks the port, the family works and the original failure was
// about the port.
func familyAvailable(ctx context.Context, lc *net.ListenConfig, address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}

	probe, err := lc.Listen(ctx, networkTCP, net.JoinHostPort(host, "0"))
	if err != nil {
		return false
	}

	_ = probe.Close()

	return true
}
