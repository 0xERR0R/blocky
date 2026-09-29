// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xERR0R/blocky/auth/authmodels"
)

// --- fakeStore ---------------------------------------------------------

// fakeStore implements SessionStore for middleware tests. No SQLite.
type fakeStore struct {
	mu       sync.Mutex
	hasUsers bool
	sessions map[string]*authmodels.Session
	users    map[uint]*authmodels.User

	extendCalls atomic.Int32
	revokeCh    chan uint
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		hasUsers: true,
		sessions: make(map[string]*authmodels.Session),
		users:    make(map[uint]*authmodels.User),
		revokeCh: make(chan uint, 16),
	}
}

func (f *fakeStore) HasUsers() bool { return f.hasUsers }

func (f *fakeStore) GetSession(id string) (*authmodels.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	s, ok := f.sessions[id]
	if !ok {
		return nil, errors.New("not found")
	}

	if time.Now().After(s.ExpiresAt) {
		return nil, errors.New("expired")
	}

	c := *s

	return &c, nil
}

func (f *fakeStore) GetUser(id uint) (*authmodels.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[id]
	if !ok {
		return nil, errors.New("not found")
	}

	c := *u

	return &c, nil
}

func (f *fakeStore) ExtendSession(id string, newExpiry time.Time) error {
	f.extendCalls.Add(1)

	f.mu.Lock()
	defer f.mu.Unlock()

	if s, ok := f.sessions[id]; ok && s.ExpiresAt.Before(newExpiry) {
		s.ExpiresAt = newExpiry
	}

	return nil
}

func (f *fakeStore) SessionRevoked() <-chan uint { return f.revokeCh }

// passthrough is the innermost handler in the middleware chain for tests.
// It writes 200 and echoes any user present in context via a header so tests
// can assert context propagation without bodies.
var passthrough = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if u := UserFromContext(r.Context()); u != nil {
		w.Header().Set("X-Test-User", u.Username)
		w.Header().Set("X-Test-Role", u.Role)
	}

	if s := SessionFromContext(r.Context()); s != nil {
		w.Header().Set("X-Test-Session-ID", s.ID)
		w.Header().Set("X-Test-Session-Expires",
			s.ExpiresAt.UTC().Format(time.RFC3339Nano))
	}

	w.WriteHeader(http.StatusOK)
})

func decodeErr(t *testing.T, body []byte) map[string]string {
	t.Helper()

	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode err body: %v (body=%q)", err, body)
	}

	return m
}

// --- RequireAuth -------------------------------------------------------

func TestRequireAuth_NoUsers_APIReturnsSetupRequired(t *testing.T) {
	s := newFakeStore()
	s.hasUsers = false

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/blocking/status", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rec.Code)
	}

	body := decodeErr(t, rec.Body.Bytes())
	if body["error"] != "setup_required" {
		t.Fatalf("error code: got %q want setup_required", body["error"])
	}
}

func TestRequireAuth_NoUsers_SetupPostAllowed(t *testing.T) {
	s := newFakeStore()
	s.hasUsers = false

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("setup POST should pass through; got %d", rec.Code)
	}
}

func TestRequireAuth_NoUsers_NonAPIPassthrough(t *testing.T) {
	s := newFakeStore()
	s.hasUsers = false

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("non-API should pass through when no users; got %d", rec.Code)
	}
}

func TestRequireAuth_NoCookie_APIUnauthorized(t *testing.T) {
	s := newFakeStore()

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/blocking/status", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rec.Code)
	}

	body := decodeErr(t, rec.Body.Bytes())
	if body["error"] != "unauthorized" {
		t.Fatalf("error code: got %q want unauthorized", body["error"])
	}
}

func TestRequireAuth_NoCookie_NonAPIPassthrough(t *testing.T) {
	s := newFakeStore()

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("non-API should pass through without cookie; got %d", rec.Code)
	}
}

func TestRequireAuth_ExpiredSession_APIUnauthorized(t *testing.T) {
	s := newFakeStore()
	s.sessions["tok"] = &authmodels.Session{
		ID:        "tok",
		UserID:    1,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	s.users[1] = &authmodels.User{ID: 1, Username: "alice", Role: RoleAdmin}

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/blocking/status", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok"})
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired session should 401 on /api/*; got %d", rec.Code)
	}
}

func TestRequireAuth_ValidSession_AttachesUser(t *testing.T) {
	s := newFakeStore()
	s.sessions["tok"] = &authmodels.Session{
		ID:        "tok",
		UserID:    1,
		ExpiresAt: time.Now().Add(SessionDuration),
	}
	s.users[1] = &authmodels.User{ID: 1, Username: "alice", Role: RoleAdmin}

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/blocking/status", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok"})
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("valid session should pass; got %d", rec.Code)
	}

	if got := rec.Header().Get("X-Test-User"); got != "alice" {
		t.Fatalf("user not attached to context: got %q", got)
	}

	if got := rec.Header().Get("X-Test-Role"); got != RoleAdmin {
		t.Fatalf("role not attached: got %q", got)
	}

	if n := s.extendCalls.Load(); n != 0 {
		t.Fatalf("ExtendSession should not run outside threshold; got %d calls", n)
	}
}

func TestRequireAuth_SlidingRenewal_CallsExtendAndSetsCookie(t *testing.T) {
	s := newFakeStore()
	// Expiry within the sliding-renewal window.
	s.sessions["tok"] = &authmodels.Session{
		ID:        "tok",
		UserID:    1,
		ExpiresAt: time.Now().Add(SessionSlidingThreshold / 2),
	}
	s.users[1] = &authmodels.User{ID: 1, Username: "alice", Role: RoleAdmin}

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/blocking/status", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok"})
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("renewed request should succeed; got %d", rec.Code)
	}

	if n := s.extendCalls.Load(); n != 1 {
		t.Fatalf("ExtendSession should be called exactly once; got %d", n)
	}

	// Verify a renewed Set-Cookie with the same cookie name went out.
	setCookies := rec.Result().Cookies()
	var renewed *http.Cookie

	for _, c := range setCookies {
		if c.Name == SessionCookieName {
			renewed = c

			break
		}
	}

	if renewed == nil {
		t.Fatalf("no renewed cookie emitted; got %v", setCookies)
	}

	if renewed.Value != "tok" {
		t.Fatalf("renewed cookie value: got %q want tok", renewed.Value)
	}

	if renewed.MaxAge != int(SessionDuration.Seconds()) {
		t.Fatalf("renewed MaxAge: got %d want %d", renewed.MaxAge, int(SessionDuration.Seconds()))
	}

	if !renewed.HttpOnly {
		t.Fatalf("renewed cookie should be HttpOnly")
	}
}

func TestRequireAuth_NoCookie_WrongMethodOnSetup_Rejected(t *testing.T) {
	s := newFakeStore()
	s.hasUsers = false

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/setup", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/auth/setup should be 401 setup_required (only POST allowed); got %d", rec.Code)
	}
}

// --- /docs/* gating (GRA-652, decision D7) -----------------------------

// The docs routes describe the admin API and its configuration. They sit
// outside /api/, so they used to ride RequireAuth's non-API passthrough and
// answer 200 to anyone; auth.EnforcesAuth now covers them.

func TestRequireAuth_NoCookie_DocsUnauthorized(t *testing.T) {
	s := newFakeStore()

	h := RequireAuth(s)(passthrough)

	for _, path := range []string{"/docs/openapi.yaml", "/docs/config.schema.json"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without cookie: got %d want 401", path, rec.Code)
		}

		if body := decodeErr(t, rec.Body.Bytes()); body["error"] != "unauthorized" {
			t.Fatalf("%s error code: got %q want unauthorized", path, body["error"])
		}
	}
}

func TestRequireAuth_NoUsers_DocsReturnsSetupRequired(t *testing.T) {
	s := newFakeStore()
	s.hasUsers = false

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/openapi.yaml", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rec.Code)
	}

	if body := decodeErr(t, rec.Body.Bytes()); body["error"] != "setup_required" {
		t.Fatalf("error code: got %q want setup_required", body["error"])
	}
}

func TestRequireAuth_ValidSession_DocsPass(t *testing.T) {
	s := newFakeStore()
	s.sessions["tok"] = &authmodels.Session{
		ID:        "tok",
		UserID:    1,
		ExpiresAt: time.Now().Add(SessionDuration),
	}
	s.users[1] = &authmodels.User{ID: 1, Username: "alice", Role: RoleAdmin}

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/openapi.yaml", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok"})
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("valid session should reach the docs handler; got %d", rec.Code)
	}
}

// TestEnforcesAuth_ShellStaysOpen is the regression guard on the other side of
// the decision: gating the SPA shell, its assets or robots.txt would serve a
// 401 in place of the login page, locking the user out of their own server.
func TestEnforcesAuth_ShellStaysOpen(t *testing.T) {
	gated := []string{
		"/api/version",
		"/docs/openapi.yaml",
		"/docs/config.schema.json",
	}

	public := []string{
		"/",
		"/ui/",
		"/ui/index.html",
		"/static/rapidoc.html",
		"/robots.txt",
	}

	for _, p := range gated {
		if !EnforcesAuth(p) {
			t.Fatalf("%s must be gated", p)
		}
	}

	for _, p := range public {
		if EnforcesAuth(p) {
			t.Fatalf("%s must stay reachable without a session", p)
		}
	}
}

// --- RequireRole -------------------------------------------------------

// withUser wraps next with a handler that attaches u to the request
// context under the same key RequireAuth uses, so tests of downstream
// middleware can skip the full auth flow.
func withUser(u *authmodels.User, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if u != nil {
			ctx = context.WithValue(ctx, userKey, u)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func TestRequireRole_AdminPasses(t *testing.T) {
	h := withUser(&authmodels.User{ID: 1, Role: RoleAdmin},
		RequireRole(RoleAdmin)(passthrough))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("admin should pass RequireRole(admin); got %d", rec.Code)
	}
}

func TestRequireRole_ViewerRejected(t *testing.T) {
	h := withUser(&authmodels.User{ID: 2, Role: RoleViewer},
		RequireRole(RoleAdmin)(passthrough))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer should be 403 on RequireRole(admin); got %d", rec.Code)
	}

	body := decodeErr(t, rec.Body.Bytes())
	if body["error"] != "forbidden" {
		t.Fatalf("error code: got %q want forbidden", body["error"])
	}
}

func TestRequireRole_NoUserRejected(t *testing.T) {
	h := RequireRole(RoleAdmin)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("no user should be 403; got %d", rec.Code)
	}
}

// --- RequireAdminForMutations ------------------------------------------

func TestRequireAdminForMutations_GETViewerPasses(t *testing.T) {
	h := withUser(&authmodels.User{ID: 2, Role: RoleViewer},
		RequireAdminForMutations()(passthrough))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("viewer GET should pass; got %d", rec.Code)
	}
}

func TestRequireAdminForMutations_POSTViewerRejected(t *testing.T) {
	h := withUser(&authmodels.User{ID: 2, Role: RoleViewer},
		RequireAdminForMutations()(passthrough))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/config", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST should be 403; got %d", rec.Code)
	}
}

func TestRequireAdminForMutations_POSTAdminPasses(t *testing.T) {
	h := withUser(&authmodels.User{ID: 1, Role: RoleAdmin},
		RequireAdminForMutations()(passthrough))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/config", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("admin POST should pass; got %d", rec.Code)
	}
}

func TestRequireAdminForMutations_DELETEViewerRejected(t *testing.T) {
	h := withUser(&authmodels.User{ID: 2, Role: RoleViewer},
		RequireAdminForMutations()(passthrough))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/config/x", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer DELETE should be 403; got %d", rec.Code)
	}
}

// --- RequireCSRFHeader -------------------------------------------------

func TestRequireCSRFHeader_MissingRejected(t *testing.T) {
	h := RequireCSRFHeader()(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/config", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing header should 403; got %d", rec.Code)
	}

	body := decodeErr(t, rec.Body.Bytes())
	if !strings.Contains(body["message"], "X-Requested-With") {
		t.Fatalf("message should mention X-Requested-With; got %q", body["message"])
	}
}

func TestRequireCSRFHeader_PresentPasses(t *testing.T) {
	h := RequireCSRFHeader()(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/config", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("present header should pass; got %d", rec.Code)
	}
}

func TestRequireCSRFHeader_GETPassesWithoutHeader(t *testing.T) {
	h := RequireCSRFHeader()(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET should pass CSRF without header; got %d", rec.Code)
	}
}

// --- UserFromContext ---------------------------------------------------

func TestUserFromContext_NilWhenAbsent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if u := UserFromContext(req.Context()); u != nil {
		t.Fatalf("expected nil user; got %+v", u)
	}
}

// --- SessionFromContext ------------------------------------------------

func TestSessionFromContext_NilWhenAbsent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if s := SessionFromContext(req.Context()); s != nil {
		t.Fatalf("expected nil session; got %+v", s)
	}
}

func TestRequireAuth_ValidSession_AttachesSessionToContext(t *testing.T) {
	s := newFakeStore()
	expires := time.Now().Add(SessionDuration)
	s.sessions["tok"] = &authmodels.Session{
		ID:        "tok",
		UserID:    1,
		ExpiresAt: expires,
	}
	s.users[1] = &authmodels.User{ID: 1, Username: "alice", Role: RoleAdmin}

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/blocking/status", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok"})
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("valid session should pass; got %d", rec.Code)
	}

	if got := rec.Header().Get("X-Test-Session-ID"); got != "tok" {
		t.Fatalf("session not attached to context: got %q", got)
	}

	// The expiry in context should match what the store returned (no
	// sliding renewal applied when far from the threshold).
	got := rec.Header().Get("X-Test-Session-Expires")
	if got == "" {
		t.Fatal("expected session expiry header")
	}

	parsed, err := time.Parse(time.RFC3339Nano, got)
	if err != nil {
		t.Fatalf("parse session expiry header: %v", err)
	}

	if !parsed.Equal(expires) {
		t.Fatalf("session expiry in context = %v, want %v", parsed, expires)
	}
}

func TestRequireAuth_SlidingRenewal_ContextExpiryIsExtended(t *testing.T) {
	s := newFakeStore()
	// Expiry within the sliding-renewal window.
	s.sessions["tok"] = &authmodels.Session{
		ID:        "tok",
		UserID:    1,
		ExpiresAt: time.Now().Add(SessionSlidingThreshold / 2),
	}
	s.users[1] = &authmodels.User{ID: 1, Username: "alice", Role: RoleAdmin}

	h := RequireAuth(s)(passthrough)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/blocking/status", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok"})

	before := time.Now()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("renewed request should succeed; got %d", rec.Code)
	}

	got := rec.Header().Get("X-Test-Session-Expires")
	if got == "" {
		t.Fatal("expected session expiry header after renewal")
	}

	parsed, err := time.Parse(time.RFC3339Nano, got)
	if err != nil {
		t.Fatalf("parse session expiry header: %v", err)
	}

	// After sliding renewal, the context expiry should be roughly
	// time.Now() + SessionDuration — strictly more than before + half the
	// sliding threshold.
	minExpected := before.Add(SessionSlidingThreshold)
	if parsed.Before(minExpected) {
		t.Fatalf("context session expiry not extended: got %v, want >= %v",
			parsed, minExpected)
	}
}
