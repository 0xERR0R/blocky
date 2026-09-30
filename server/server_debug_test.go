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
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/helpertest"
)

// debugPaths is the diagnostics surface: every page this listener exists to
// serve, and every page that must not appear on the HTTP API port.
var debugPaths = []string{
	"/debug/pprof/",
	"/debug/pprof/cmdline",
	"/debug/pprof/heap",
	"/debug/vars",
}

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

	for _, path := range append([]string{"/debug/"}, debugPaths...) {
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

	// /debug/ redirects to /debug/pprof/; the rest answer directly.
	assertDebugStatus(t, router, "127.0.0.1:6060", "/debug/", http.StatusMovedPermanently)

	for _, path := range debugPaths {
		assertDebugStatus(t, router, "127.0.0.1:6060", path, http.StatusOK)
	}
}

// TestDebugRouterRejectsNonLoopbackHost covers the DNS-rebinding case. Binding
// loopback keeps packets from off-box, but a browser page on the box whose
// hostname rebinds to 127.0.0.1 reaches this listener with a Host of its own
// choosing — and a request that gets through is a heap dump, or a
// `?seconds=100000` CPU pin that needs no CORS at all to land.
func TestDebugRouterRejectsNonLoopbackHost(t *testing.T) {
	router := newDebugRouter()

	for _, host := range []string{"evil.example.com:6060", "blocky.lan:6060", "192.168.1.10:6060", ""} {
		assertDebugStatus(t, router, host, "/debug/pprof/heap", http.StatusMisdirectedRequest)
	}
}

// TestDebugRouterAcceptsLoopbackHostForms pins the hosts real callers send:
// `go tool pprof http://127.0.0.1:6060/...` straight at the listener, and
// localhost through an SSH tunnel or `kubectl port-forward`.
func TestDebugRouterAcceptsLoopbackHostForms(t *testing.T) {
	router := newDebugRouter()

	for _, host := range []string{
		"127.0.0.1:6060", "localhost:6060", "LOCALHOST:6060",
		"[::1]:6060", "127.0.0.2:6060", "localhost",
	} {
		assertDebugStatus(t, router, host, "/debug/vars", http.StatusOK)
	}
}

// TestDebugServerHasNoCORSPolicy is the other half of the rebinding defense. The
// fork's same-origin CORS policy mirrors Origin with
// Access-Control-Allow-Credentials whenever Origin's host matches the request
// Host — and under rebinding a page controls both, which would make the response
// body readable by its JavaScript. The debug listener must carry no CORS policy
// at all, which is why it is built with newBareHTTPServer rather than
// newHTTPServer.
func TestDebugServerHasNoCORSPolicy(t *testing.T) {
	srv := newBareHTTPServer(debugServerName, newDebugRouter())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://127.0.0.1:6060/debug/pprof/heap", nil)
	req.Host = "127.0.0.1:6060"
	req.Header.Set("Origin", "http://127.0.0.1:6060")

	rec := httptest.NewRecorder()
	srv.inner.Handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("debug response carries Access-Control-Allow-Origin: %q, want none", got)
	}

	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("debug response carries Access-Control-Allow-Credentials: %q, want none", got)
	}
}

// TestDebugServerKeepsStandardTimeouts documents why the debug listener does not
// need special ones. net/http/pprof extends the per-request write deadline by
// ?seconds= itself (configureWriteDeadline, and only when WriteTimeout > 0), so
// keeping serverWriteTimeout both bounds ordinary responses and lets a long
// `go tool pprof -seconds=120` run to completion.
func TestDebugServerKeepsStandardTimeouts(t *testing.T) {
	srv := newBareHTTPServer(debugServerName, newDebugRouter())

	if srv.inner.WriteTimeout != serverWriteTimeout {
		t.Errorf("debug server WriteTimeout = %v, want %v", srv.inner.WriteTimeout, serverWriteTimeout)
	}

	if srv.inner.ReadHeaderTimeout != serverReadHeaderTimeout {
		t.Errorf("debug server ReadHeaderTimeout = %v, want %v",
			srv.inner.ReadHeaderTimeout, serverReadHeaderTimeout)
	}
}

// TestAddDebugListenersDisabled pins the default: nothing is bound, so an
// operator who never opted in has no diagnostics port at all.
func TestAddDebugListenersDisabled(t *testing.T) {
	s := &Server{servers: map[net.Listener]*httpServer{}}

	if err := s.addDebugListeners(t.Context(), &config.Config{}); err != nil {
		t.Fatalf("addDebugListeners with debug disabled: %v", err)
	}

	if len(s.servers) != 0 {
		t.Errorf("registered %d listeners with debug disabled, want 0", len(s.servers))
	}
}

// TestAddDebugListenersRegistersForLifecycle covers the seam between the config
// and the server: the listeners have to land in Server.servers, because that map
// is what Start serves and what Stop closes. A refactor that bound them into a
// local slice would leave an enabled listener unserved, or a port Stop never
// releases, while every isolated test in this file still passed.
func TestAddDebugListenersRegistersForLifecycle(t *testing.T) {
	port := freeLoopbackPort(t)
	cfg := &config.Config{Debug: config.Debug{Enable: true, Port: port}}

	s := &Server{cfg: cfg, servers: map[net.Listener]*httpServer{}}

	if err := s.addDebugListeners(t.Context(), cfg); err != nil {
		t.Fatalf("addDebugListeners: %v", err)
	}

	if len(s.servers) == 0 {
		t.Fatal("addDebugListeners registered no listeners")
	}

	for l, srv := range s.servers {
		if srv.String() != debugServerName {
			t.Errorf("listener %s registered under %q, want %q", l.Addr(), srv, debugServerName)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, len(s.servers))
	s.Start(ctx, errCh)

	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))) + "/debug/vars"

	resp, err := httpGetEventually(t, url)
	if err != nil {
		t.Fatalf("GET %s after Start: %v", url, err)
	}

	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s after Start: got %d, want 200", url, resp.StatusCode)
	}

	if err := s.Stop(t.Context()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Stop promises the ports are back by the time it returns, which is the
	// property a restart depends on.
	for _, address := range cfg.Debug.ListenAddresses() {
		rebound, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", address)
		if err != nil {
			t.Errorf("Stop did not release %s: %v", address, err)

			continue
		}

		_ = rebound.Close()
	}

	select {
	case err := <-errCh:
		t.Errorf("unexpected error from the debug listener: %v", err)
	default:
	}
}

// TestCreateDebugListenersBindLoopbackOnly pins the property the whole design
// rests on: the diagnostics listener is not reachable off-box, and no config
// value can make it so.
func TestCreateDebugListenersBindLoopbackOnly(t *testing.T) {
	port := freeLoopbackPort(t)

	listeners, err := createDebugListeners(t.Context(), &config.Debug{Enable: true, Port: port})
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

// TestCreateDebugListenersRejectsPortConflict covers the distinction
// createDebugListeners has to draw. A host missing an IP family is tolerated with
// a warning; a port already in use is not, because the result would be a listener
// present on one family and absent on the other. One occupied address is enough
// to fail the whole thing.
func TestCreateDebugListenersRejectsPortConflict(t *testing.T) {
	port := freeLoopbackPort(t)
	addresses := (&config.Debug{Port: port}).ListenAddresses()

	for _, occupied := range addresses {
		blocker, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", occupied)
		if err != nil {
			// This host does not have that family at all, which is the
			// tolerated case rather than the one under test.
			continue
		}

		listeners, err := createDebugListeners(t.Context(), &config.Debug{Enable: true, Port: port})
		if err == nil {
			closeAll(listeners)
			_ = blocker.Close()
			t.Fatalf("expected an error with %s already bound", occupied)
		}

		if len(listeners) != 0 {
			t.Errorf("createDebugListeners returned %d listeners alongside an error; "+
				"they leak because the caller has no handle on them", len(listeners))
		}

		_ = blocker.Close()
	}
}

func assertDebugStatus(t *testing.T, router http.Handler, host, path string, want int) {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.invalid"+path, nil)
	req.Host = host

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != want {
		t.Errorf("GET %s with Host %q: got %d, want %d", path, host, rec.Code, want)
	}
}

// httpGetEventually retries until the listener's Serve goroutine is accepting.
// Start launches it asynchronously, so the first attempt can legitimately lose
// the race.
func httpGetEventually(t *testing.T, url string) (*http.Response, error) {
	t.Helper()

	const attempts = 100

	var err error

	for range attempts {
		var req *http.Request

		req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		var resp *http.Response

		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			return resp, nil
		}

		time.Sleep(10 * time.Millisecond)
	}

	return nil, err
}

// freeLoopbackPort returns a port createDebugListeners can bind on both
// loopback families.
//
// It used to bind 127.0.0.1:0, read the assigned port back and close the probe,
// which meant the number came from the kernel's ephemeral range — the same
// range every outbound socket in the process draws from — and was only known to
// be free on IPv4, only until the probe closed. helpertest.NextFreePort draws
// from a band outside that range and checks both families, so nothing else can
// be holding the port when the caller binds it. See GRA-650.
func freeLoopbackPort(t *testing.T) uint16 {
	t.Helper()

	return uint16(helpertest.NextFreePort())
}
