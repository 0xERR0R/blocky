// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/0xERR0R/blocky/config"
)

// TestDebugNotServedOnAPIPort is the regression guard for GRA-647.
//
// pprof used to be mounted at /debug on the same router as the REST API and the
// SPA, inside the authenticated group. That looked safe and was not: RequireAuth
// only rejects /api/* paths, so every pprof and expvar GET was readable without
// a session by anything that could reach the API port. The fix is structural —
// the diagnostics surface is not on this router at all — so the assertion is
// structural too.
func TestDebugNotServedOnAPIPort(t *testing.T) {
	router := buildContractRouter(t)

	for _, path := range []string{
		"/debug/",
		"/debug/pprof/",
		"/debug/pprof/cmdline",
		"/debug/pprof/heap",
		"/debug/vars",
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))

		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s on the API router: got %d, want 404 (pprof must live on "+
				"the loopback debug listener only)", path, rec.Code)
		}
	}
}

func TestDebugRouterServesPprofAndExpvar(t *testing.T) {
	router := newDebugRouter()

	cases := map[string]int{
		"/debug/":              http.StatusMovedPermanently, // -> /debug/pprof/
		"/debug/pprof/":        http.StatusOK,
		"/debug/pprof/cmdline": http.StatusOK,
		"/debug/pprof/heap":    http.StatusOK,
		"/debug/vars":          http.StatusOK,
	}

	for path, want := range cases {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))

		if rec.Code != want {
			t.Errorf("GET %s on the debug router: got %d, want %d", path, rec.Code, want)
		}
	}
}

// TestCreateDebugListenersBindLoopbackOnly pins the property the whole design
// rests on: the diagnostics listener is not reachable off-box, and no config
// value can make it so.
func TestCreateDebugListenersBindLoopbackOnly(t *testing.T) {
	port := freeLoopbackPort(t)

	cfg := &config.Debug{Enable: true, Port: port}

	listeners, err := createDebugListeners(context.Background(), cfg)
	if err != nil {
		t.Fatalf("create debug listeners: %v", err)
	}

	t.Cleanup(func() { closeAll(listeners) })

	if len(listeners) == 0 {
		t.Fatal("no debug listeners bound")
	}

	for _, l := range listeners {
		addr, ok := l.Addr().(*net.TCPAddr)
		if !ok {
			t.Fatalf("listener %s is not TCP", l.Addr())
		}

		if !addr.IP.IsLoopback() {
			t.Errorf("debug listener bound %s, which is not loopback", addr)
		}

		if addr.Port != int(port) {
			t.Errorf("debug listener bound port %d, want %d", addr.Port, port)
		}
	}
}

// TestCreateDebugListenersReportsTotalFailure covers the other half: one family
// failing is tolerated (hosts routinely lack IPv6), but failing everywhere is an
// error rather than a silently missing listener.
func TestCreateDebugListenersReportsTotalFailure(t *testing.T) {
	port := freeLoopbackPort(t)

	blockers := make([]net.Listener, 0, 2)
	lc := &net.ListenConfig{}

	for _, address := range (&config.Debug{Port: port}).ListenAddresses() {
		l, err := lc.Listen(t.Context(), "tcp", address)
		if err != nil {
			// No IPv6 (or no IPv4) on this host: that family would have failed
			// for createDebugListeners too, which is the state we want.
			continue
		}

		blockers = append(blockers, l)
	}

	t.Cleanup(func() { closeAll(blockers) })

	if len(blockers) == 0 {
		t.Skip("could not bind any loopback address to occupy the port")
	}

	listeners, err := createDebugListeners(context.Background(), &config.Debug{Enable: true, Port: port})
	if err == nil {
		closeAll(listeners)
		t.Fatal("expected an error when every debug address is already bound")
	}
}

// TestDebugHTTPServerHasNoWriteTimeout pins the reason the debug listener does
// not reuse newHTTPServer as-is: `go tool pprof -seconds=120` streams for longer
// than serverWriteTimeout, which would truncate the profile.
func TestDebugHTTPServerHasNoWriteTimeout(t *testing.T) {
	srv := newDebugHTTPServer(newDebugRouter())

	if srv.inner.WriteTimeout != 0 {
		t.Errorf("debug server WriteTimeout = %v, want 0", srv.inner.WriteTimeout)
	}

	if srv.inner.ReadHeaderTimeout != serverReadHeaderTimeout {
		t.Errorf("debug server ReadHeaderTimeout = %v, want %v",
			srv.inner.ReadHeaderTimeout, serverReadHeaderTimeout)
	}
}

// freeLoopbackPort returns a port that was free on loopback a moment ago. The
// listener is closed before returning so the caller can bind it on both
// families, which is the shape createDebugListeners needs.
func freeLoopbackPort(t *testing.T) uint16 {
	t.Helper()

	lc := &net.ListenConfig{}

	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}

	_, portStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		_ = l.Close()
		t.Fatalf("split %s: %v", l.Addr(), err)
	}

	if err := l.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}

	return uint16(port)
}
