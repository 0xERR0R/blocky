// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xERR0R/blocky/auth"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/configstore"

	"github.com/go-chi/chi/v5"
)

// newRouteShapeServer builds a minimal router that exercises the same
// public/authenticated split registerUIRoutes wires up in production, but
// without DoH, TLS, or the OpenAPI StrictServerInterface (which requires a
// live resolver chain). Only the shape-level behaviors are tested here:
//
//   - Public endpoints (metrics path, mobileconfig, login, setup) reachable
//     without a session cookie.
//   - /api/* routes under the auth group return 401 without a cookie.
//   - /docs/* routes under the auth group return 401 without a cookie and
//     serve with one (GRA-652 / decision D7).
//
// The intent is to catch route-group drift — someone accidentally moving a
// public endpoint into the authenticated group or vice-versa.
func newRouteShapeServer(t *testing.T) (http.Handler, *configstore.ConfigStore) {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "shape.db")

	store, err := configstore.Open(dbPath)
	if err != nil {
		t.Fatalf("open configstore: %v", err)
	}

	t.Cleanup(func() { _ = store.Close() })

	router := chi.NewRouter()

	// --- Public ---

	// Prometheus metrics path — public by design. We mount a stub at
	// /metrics rather than call metrics.Start because metrics.Start
	// mutates the shared prometheus.Registry and would leak across tests.
	// The goal of this test is route-shape, not metrics correctness.
	router.Get("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("# metrics\n"))
	})

	// Mobileconfig — public by design.
	router.Get("/api/mobileconfig/{slug}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("stub"))
	})

	// Public auth routes (login, setup). CSRF is applied internally by
	// RegisterPublicRoutes, so no r.Use(...) here.
	registerAuthRoutes(router, store)

	// --- Authenticated group ---
	router.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth(store))
		r.Use(auth.RequireCSRFHeader())

		registerAuthenticatedAuthRoutes(r, store)

		r.Group(func(rr chi.Router) {
			rr.Use(auth.RequireAdminForMutations())

			// A representative admin API route to prove the group gates it.
			rr.Get("/api/stats", handleStats)
			rr.Get("/api/version", handleVersion)
		})

		// The real docs routes. They sit outside /api/, so being inside this
		// group is not on its own enough to gate them — auth.EnforcesAuth has
		// to cover them too, which is what the docs specs below check.
		configureDocsHandler(r)

		// The index page. Public (RequireAuth passes / through), but its link
		// list depends on whether a session was attached.
		configureRootHandler(&config.Config{}, r)
	})

	return router, store
}

// newRouteShapeServerNoUsers returns the shape-test router with no users
// seeded, so RequireAuth's first-run "setup_required" branch is exercised.
func newRouteShapeServerNoUsers(t *testing.T) http.Handler {
	t.Helper()

	h, _ := newRouteShapeServer(t)

	return h
}

// newRouteShapeServerWithAdmin seeds an admin user so RequireAuth's
// "no users → setup_required" branch is bypassed and the
// missing-cookie "unauthorized" branch is exercised instead.
func newRouteShapeServerWithAdmin(t *testing.T) http.Handler {
	t.Helper()

	h, store := newRouteShapeServer(t)

	hash, err := auth.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if err := store.CreateUser(&configstore.User{
		Username:     "admin",
		PasswordHash: hash,
		Role:         auth.RoleAdmin,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	return h
}

func doReq(t *testing.T, h http.Handler, method, path string, setHeader ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequest(method, path, nil)
	for _, fn := range setHeader {
		fn(r)
	}

	r.RemoteAddr = "127.0.0.1:55555"

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	return w
}

// TestRouteShape_MetricsPublic: the Prometheus metrics path must be reachable
// without a session cookie, because monitoring systems (and, on the DNS
// side, the k8s health probe) scrape without credentials.
func TestRouteShape_MetricsPublic(t *testing.T) {
	h := newRouteShapeServerWithAdmin(t)

	w := doReq(t, h, http.MethodGet, "/metrics")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics: want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestRouteShape_MobileconfigPublic: mobileconfig downloads are consumed by
// MDM systems (Apple Configurator / profile installer on iOS) that cannot
// carry a session cookie.
func TestRouteShape_MobileconfigPublic(t *testing.T) {
	h := newRouteShapeServerWithAdmin(t)

	w := doReq(t, h, http.MethodGet, "/api/mobileconfig/example")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/mobileconfig/example: want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestRouteShape_APIRequiresAuth: a representative API route on the
// authenticated group must return 401 with the `unauthorized` envelope code
// when there is no session cookie.
func TestRouteShape_APIRequiresAuth(t *testing.T) {
	h := newRouteShapeServerWithAdmin(t)

	w := doReq(t, h, http.MethodGet, "/api/stats")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/stats: want 401, got %d: %s", w.Code, w.Body.String())
	}

	var body struct {
		Error string `json:"error"`
	}

	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode envelope: %v (body=%q)", err, w.Body.String())
	}

	if body.Error != "unauthorized" {
		t.Fatalf("error code: want %q, got %q (body=%q)", "unauthorized", body.Error, w.Body.String())
	}
}

// TestRouteShape_APIFirstRunSetupRequired: with no users seeded, API routes
// return 401 setup_required so the SPA can route the user into the setup
// wizard.
func TestRouteShape_APIFirstRunSetupRequired(t *testing.T) {
	h := newRouteShapeServerNoUsers(t)

	w := doReq(t, h, http.MethodGet, "/api/stats")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/stats (no users): want 401, got %d: %s", w.Code, w.Body.String())
	}

	var body struct {
		Error string `json:"error"`
	}

	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode envelope: %v (body=%q)", err, w.Body.String())
	}

	if body.Error != "setup_required" {
		t.Fatalf("error code: want %q, got %q (body=%q)", "setup_required", body.Error, w.Body.String())
	}
}

// TestRouteShape_LoginReachablePublic: POST /api/auth/login must be reachable
// without a session cookie. It may legitimately return 400 (bad body) or 401
// invalid_credentials, but NOT the auth-middleware envelope codes
// (unauthorized / setup_required) — those would mean the route is
// accidentally gated by RequireAuth.
func TestRouteShape_LoginReachablePublic(t *testing.T) {
	h := newRouteShapeServerWithAdmin(t)

	setCSRF := func(r *http.Request) {
		r.Header.Set("X-Requested-With", "test")
	}

	w := doReq(t, h, http.MethodPost, "/api/auth/login", setCSRF)

	var body struct {
		Error string `json:"error"`
	}

	// Body may be empty for some non-JSON error paths; that's fine.
	_ = json.Unmarshal(w.Body.Bytes(), &body)

	if body.Error == "unauthorized" || body.Error == "setup_required" {
		t.Fatalf("POST /api/auth/login is gated by RequireAuth (should be public): code=%d body=%q", w.Code, w.Body.String())
	}
}

// TestRouteShape_SetupReachableFirstRun: POST /api/auth/setup must be
// reachable during first-run. The handler will 400 on empty body but must
// not return the RequireAuth envelope.
func TestRouteShape_SetupReachableFirstRun(t *testing.T) {
	h := newRouteShapeServerNoUsers(t)

	setCSRF := func(r *http.Request) {
		r.Header.Set("X-Requested-With", "test")
	}

	w := doReq(t, h, http.MethodPost, "/api/auth/setup", setCSRF)

	var body struct {
		Error string `json:"error"`
	}

	_ = json.Unmarshal(w.Body.Bytes(), &body)

	if body.Error == "unauthorized" {
		t.Fatalf("POST /api/auth/setup during first-run is gated (should be open): code=%d body=%q", w.Code, w.Body.String())
	}
}

// shapeAdminPassword is the password newRouteShapeServerWithAdmin seeds, so
// specs that need a real session can log in through the public route rather
// than forging a cookie.
const shapeAdminPassword = "correct-horse-battery-staple"

// loginCookie logs the seeded admin in and returns the session cookie.
func loginCookie(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()

	body := `{"username":"admin","password":"` + shapeAdminPassword + `"}`

	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Requested-With", "test")
	r.RemoteAddr = "127.0.0.1:55555"

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("login: want 200, got %d: %s", w.Code, w.Body.String())
	}

	for _, c := range w.Result().Cookies() {
		if c.Name == auth.SessionCookieName || c.Name == auth.SessionCookieNameSecure {
			return c
		}
	}

	t.Fatalf("login returned no session cookie (set-cookie=%q)", w.Header().Values("Set-Cookie"))

	return nil
}

// docsRoutes are the two routes decision D7 put behind authentication.
var docsRoutes = []string{"/docs/openapi.yaml", "/docs/config.schema.json"}

// TestRouteShape_DocsRequireAuth: the docs routes live outside /api/, so they
// used to ride RequireAuth's passthrough and answer 200 to anyone. They must
// now return the `unauthorized` envelope without a session (GRA-652 / D7).
func TestRouteShape_DocsRequireAuth(t *testing.T) {
	h := newRouteShapeServerWithAdmin(t)

	for _, path := range docsRoutes {
		w := doReq(t, h, http.MethodGet, path)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s: want 401, got %d: %s", path, w.Code, w.Body.String())
		}

		var body struct {
			Error string `json:"error"`
		}

		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode envelope for %s: %v (body=%q)", path, err, w.Body.String())
		}

		if body.Error != "unauthorized" {
			t.Fatalf("%s error code: want %q, got %q", path, "unauthorized", body.Error)
		}
	}
}

// TestRouteShape_DocsServedWithSession: gating them must not break the
// logged-in case — rapidoc.html fetches /docs/openapi.yaml with the session
// cookie the browser already carries.
func TestRouteShape_DocsServedWithSession(t *testing.T) {
	h := newRouteShapeServerWithAdmin(t)
	cookie := loginCookie(t, h)

	withSession := func(r *http.Request) { r.AddCookie(cookie) }

	for _, path := range docsRoutes {
		w := doReq(t, h, http.MethodGet, path, withSession)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s with session: want 200, got %d: %s", path, w.Code, w.Body.String())
		}

		if w.Body.Len() == 0 {
			t.Fatalf("GET %s with session: empty body", path)
		}
	}
}

// TestRouteShape_IndexHidesGatedLinksWhenAnonymous: / stays public so the
// login screen is reachable, but it must not advertise links that now answer
// 401 to the visitor reading it.
func TestRouteShape_IndexHidesGatedLinksWhenAnonymous(t *testing.T) {
	h := newRouteShapeServerWithAdmin(t)

	w := doReq(t, h, http.MethodGet, "/")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /: want 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, `"/ui/"`) {
		t.Fatalf("anonymous index should still link the web UI; body=%q", body)
	}

	for _, path := range docsRoutes {
		if strings.Contains(body, path) {
			t.Fatalf("anonymous index links %s, which answers 401 without a session", path)
		}
	}
}

// TestRouteShape_IndexShowsGatedLinksWithSession: with a session those links
// work, so the page lists them again.
func TestRouteShape_IndexShowsGatedLinksWithSession(t *testing.T) {
	h := newRouteShapeServerWithAdmin(t)
	cookie := loginCookie(t, h)

	w := doReq(t, h, http.MethodGet, "/", func(r *http.Request) { r.AddCookie(cookie) })
	if w.Code != http.StatusOK {
		t.Fatalf("GET / with session: want 200, got %d", w.Code)
	}

	body := w.Body.String()
	for _, path := range docsRoutes {
		if !strings.Contains(body, path) {
			t.Fatalf("index with a session should link %s; body=%q", path, body)
		}
	}
}

// TestSameOriginFunc exercises the CORS same-origin mirror used by
// newCORSMiddleware. The host comparison is case-insensitive and the port
// is part of the host (a different port is a different origin).
func TestSameOriginFunc(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		origin   string
		expected bool
	}{
		{"exact match", "example.com", "https://example.com", true},
		{"exact match with port", "example.com:8080", "https://example.com:8080", true},
		{"case-insensitive host", "Example.COM", "https://example.com", true},
		{"case-insensitive scheme doesn't matter", "example.com", "HTTPS://example.com", true},
		{"different host", "example.com", "https://evil.example.com", false},
		{"different port", "example.com:8080", "https://example.com:9090", false},
		{"empty origin", "example.com", "", false},
		{"garbage origin", "example.com", "not a url", false},
		{"origin with path only", "example.com", "/relative/path", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/", nil)
			r.Host = tc.host

			got := sameOriginFunc(r, tc.origin)
			if got != tc.expected {
				t.Fatalf("sameOriginFunc(host=%q, origin=%q): got %v, want %v", tc.host, tc.origin, got, tc.expected)
			}
		})
	}
}
