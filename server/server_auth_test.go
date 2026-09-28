// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xERR0R/blocky/auth"
	"github.com/0xERR0R/blocky/configstore"

	"github.com/go-chi/chi/v5"
)

// -----------------------------------------------------------------------------
// Test harness: builds a router wired the same way Phase 5 will wire it, but
// with just the auth endpoints mounted. No CORS, no DoH, no static assets.
// -----------------------------------------------------------------------------

type testServer struct {
	t       *testing.T
	store   *configstore.ConfigStore
	handler *authHandler
	mux     http.Handler
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "auth.db")

	store, err := configstore.Open(dbPath)
	if err != nil {
		t.Fatalf("open configstore: %v", err)
	}

	t.Cleanup(func() { _ = store.Close() })

	h := newAuthHandler(store)

	r := chi.NewRouter()

	// Public routes (login/setup behind CSRF, session probe header-agnostic).
	h.RegisterPublicRoutes(r)

	// Authenticated group: RequireAuth gates entry, RequireCSRFHeader is
	// applied at the group level just like Phase 5 will do.
	r.Group(func(ag chi.Router) {
		ag.Use(auth.RequireAuth(store))
		ag.Use(auth.RequireCSRFHeader())

		h.RegisterAuthenticatedRoutes(ag)
	})

	return &testServer{t: t, store: store, handler: h, mux: r}
}

// do issues a request and returns the response for the caller to inspect.
// The X-Requested-With header is added by default on non-GET requests so
// the CSRF middleware doesn't reject tests; add `unsafe: true` via doRaw
// if a test wants to verify CSRF rejection.
func (ts *testServer) do(method, path string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	ts.t.Helper()

	return ts.doRaw(method, path, body, false, cookies...)
}

func (ts *testServer) doRaw(method, path string, body any, skipCSRF bool, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	ts.t.Helper()

	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			ts.t.Fatalf("marshal body: %v", err)
		}

		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}

	r := httptest.NewRequest(method, path, reader)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}

	if !skipCSRF && method != http.MethodGet {
		r.Header.Set("X-Requested-With", "test")
	}

	// Set a stable RemoteAddr so the rate limiter keys consistently.
	r.RemoteAddr = "127.0.0.1:54321"

	for _, c := range cookies {
		r.AddCookie(c)
	}

	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, r)

	return w
}

func mustDecode(t *testing.T, w *httptest.ResponseRecorder, dst any) {
	t.Helper()

	if err := json.Unmarshal(w.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
}

// sessionCookieFromResponse finds the session cookie the handler emitted.
// Over plain HTTP (which is what httptest simulates by default) the name is
// the non-secure one.
func sessionCookieFromResponse(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()

	for _, c := range w.Result().Cookies() {
		if c.Name == auth.SessionCookieName || c.Name == auth.SessionCookieNameSecure {
			return c
		}
	}

	t.Fatalf("no session cookie set; headers: %v", w.Header())

	return nil
}

// seedUser inserts a user via the normal CreateUser path.
func (ts *testServer) seedUser(username, password, role string) *configstore.User {
	ts.t.Helper()

	hash, err := auth.HashPassword(password)
	if err != nil {
		ts.t.Fatalf("hash: %v", err)
	}

	u := &configstore.User{
		Username:     strings.ToLower(username),
		PasswordHash: hash,
		Role:         role,
	}

	if err := ts.store.CreateUser(u); err != nil {
		ts.t.Fatalf("create user: %v", err)
	}

	return u
}

// login drives a login request end-to-end and returns the session cookie
// so subsequent authenticated calls can attach it.
func (ts *testServer) login(username, password string) *http.Cookie {
	ts.t.Helper()

	w := ts.do(http.MethodPost, "/api/auth/login",
		loginRequest{Username: username, Password: password})
	if w.Code != http.StatusOK {
		ts.t.Fatalf("login: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	return sessionCookieFromResponse(ts.t, w)
}

// -----------------------------------------------------------------------------
// Login tests
// -----------------------------------------------------------------------------

func TestLogin_Success(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	w := ts.do(http.MethodPost, "/api/auth/login",
		loginRequest{Username: "alice", Password: "correcthorsebattery"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data userResponse `json:"data"`
	}

	mustDecode(t, w, &resp)

	if resp.Data.Username != "alice" {
		t.Errorf("expected username alice, got %q", resp.Data.Username)
	}

	if resp.Data.Role != auth.RoleAdmin {
		t.Errorf("expected role admin, got %q", resp.Data.Role)
	}

	// Must set a session cookie.
	_ = sessionCookieFromResponse(t, w)
}

func TestLogin_WrongPassword(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	w := ts.do(http.MethodPost, "/api/auth/login",
		loginRequest{Username: "alice", Password: "wrongpassword!"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}

	mustDecode(t, w, &resp)

	if resp.Error != "invalid_credentials" {
		t.Errorf("expected error invalid_credentials, got %q", resp.Error)
	}
}

func TestLogin_UnknownUser(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	w := ts.do(http.MethodPost, "/api/auth/login",
		loginRequest{Username: "bob", Password: "correcthorsebattery"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// Must not leak "user not found" as a distinct error code.
	var resp struct {
		Error string `json:"error"`
	}

	mustDecode(t, w, &resp)

	if resp.Error != "invalid_credentials" {
		t.Errorf("expected error invalid_credentials, got %q", resp.Error)
	}
}

func TestLogin_CaseInsensitiveUsername(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	w := ts.do(http.MethodPost, "/api/auth/login",
		loginRequest{Username: "ALICE", Password: "correcthorsebattery"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_RateLimit(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	// 5 failed attempts -> all 401. 6th attempt -> 429 with Retry-After.
	for i := range loginBucketCap {
		w := ts.do(http.MethodPost, "/api/auth/login",
			loginRequest{Username: "alice", Password: "wrong!"})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, w.Code)
		}
	}

	w := ts.do(http.MethodPost, "/api/auth/login",
		loginRequest{Username: "alice", Password: "wrong!"})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failures, got %d: %s",
			loginBucketCap, w.Code, w.Body.String())
	}

	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Errorf("expected Retry-After header, got none")
	}
}

func TestLogin_ResetsRateLimitOnSuccess(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	// 4 failed attempts leaves 1 token.
	for range 4 {
		_ = ts.do(http.MethodPost, "/api/auth/login",
			loginRequest{Username: "alice", Password: "wrong!"})
	}

	// Successful login resets bucket.
	w := ts.do(http.MethodPost, "/api/auth/login",
		loginRequest{Username: "alice", Password: "correcthorsebattery"})
	if w.Code != http.StatusOK {
		t.Fatalf("login success: got %d", w.Code)
	}

	// After reset, we should again get 5 failure attempts before 429.
	for i := range loginBucketCap {
		w := ts.do(http.MethodPost, "/api/auth/login",
			loginRequest{Username: "alice", Password: "wrong!"})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("post-reset attempt %d: expected 401, got %d", i+1, w.Code)
		}
	}
}

func TestLogin_CSRFMissing(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	w := ts.doRaw(http.MethodPost, "/api/auth/login",
		loginRequest{Username: "alice", Password: "correcthorsebattery"}, true)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without X-Requested-With, got %d: %s",
			w.Code, w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// Setup tests
// -----------------------------------------------------------------------------

func TestSetup_FirstRunCreatesAdmin(t *testing.T) {
	ts := newTestServer(t)

	w := ts.do(http.MethodPost, "/api/auth/setup",
		setupRequest{Username: "admin", Password: "correcthorsebattery"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data userResponse `json:"data"`
	}

	mustDecode(t, w, &resp)

	if resp.Data.Username != "admin" {
		t.Errorf("expected admin, got %q", resp.Data.Username)
	}

	if resp.Data.Role != auth.RoleAdmin {
		t.Errorf("expected role admin, got %q", resp.Data.Role)
	}

	// Session cookie must be set.
	c := sessionCookieFromResponse(t, w)
	if c.Value == "" {
		t.Errorf("expected session token, got empty cookie")
	}

	// HasUsers cache must reflect the new row.
	if !ts.store.HasUsers() {
		t.Errorf("HasUsers should be true after setup")
	}
}

func TestSetup_SecondCallReturns409(t *testing.T) {
	ts := newTestServer(t)

	// First setup succeeds.
	w := ts.do(http.MethodPost, "/api/auth/setup",
		setupRequest{Username: "admin", Password: "correcthorsebattery"})
	if w.Code != http.StatusOK {
		t.Fatalf("first setup: expected 200, got %d", w.Code)
	}

	// Second setup returns 409.
	w = ts.do(http.MethodPost, "/api/auth/setup",
		setupRequest{Username: "another", Password: "anotherpassword"})
	if w.Code != http.StatusConflict {
		t.Fatalf("second setup: expected 409, got %d: %s",
			w.Code, w.Body.String())
	}

	var resp struct {
		Error string `json:"error"`
	}

	mustDecode(t, w, &resp)

	if resp.Error != "already_configured" {
		t.Errorf("expected error already_configured, got %q", resp.Error)
	}
}

func TestSetup_ConcurrentRace(t *testing.T) {
	ts := newTestServer(t)

	const n = 8

	var (
		wg       sync.WaitGroup
		successN atomic.Int32
		conflict atomic.Int32
		start    = make(chan struct{})
	)

	for i := range n {
		wg.Go(func() {
			<-start

			w := ts.do(http.MethodPost, "/api/auth/setup", setupRequest{
				Username: fmt.Sprintf("admin%d", i),
				Password: "correcthorsebattery",
			})

			switch w.Code {
			case http.StatusOK:
				successN.Add(1)
			case http.StatusConflict:
				conflict.Add(1)
			default:
				t.Errorf("goroutine %d: unexpected status %d body=%s",
					i, w.Code, w.Body.String())
			}
		})
	}

	close(start)
	wg.Wait()

	if successN.Load() != 1 {
		t.Errorf("expected exactly 1 successful setup, got %d", successN.Load())
	}

	if conflict.Load() != n-1 {
		t.Errorf("expected %d conflicts, got %d", n-1, conflict.Load())
	}

	// The one admin row must actually exist.
	users, err := ts.store.ListUsers()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}

	if len(users) != 1 {
		t.Errorf("expected exactly 1 user row, got %d", len(users))
	}
}

func TestSetup_ShortPasswordRejected(t *testing.T) {
	ts := newTestServer(t)

	w := ts.do(http.MethodPost, "/api/auth/setup",
		setupRequest{Username: "admin", Password: "short"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// -----------------------------------------------------------------------------
// Session tests
// -----------------------------------------------------------------------------

func TestSession_BeforeLoginReturns401(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	w := ts.do(http.MethodGet, "/api/auth/session", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Error string `json:"error"`
	}

	mustDecode(t, w, &resp)

	if resp.Error != "unauthorized" {
		t.Errorf("expected error unauthorized, got %q", resp.Error)
	}
}

func TestSession_SetupRequiredWhenNoUsers(t *testing.T) {
	ts := newTestServer(t)

	w := ts.do(http.MethodGet, "/api/auth/session", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Error string `json:"error"`
	}

	mustDecode(t, w, &resp)

	if resp.Error != "setup_required" {
		t.Errorf("expected error setup_required, got %q", resp.Error)
	}
}

func TestSession_AfterLoginReturnsUser(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	cookie := ts.login("alice", "correcthorsebattery")

	w := ts.do(http.MethodGet, "/api/auth/session", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data userResponse `json:"data"`
	}

	mustDecode(t, w, &resp)

	if resp.Data.Username != "alice" {
		t.Errorf("expected username alice, got %q", resp.Data.Username)
	}
}

// -----------------------------------------------------------------------------
// Logout tests
// -----------------------------------------------------------------------------

func TestLogout_DeletesSessionAndClearsCookie(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	cookie := ts.login("alice", "correcthorsebattery")

	w := ts.do(http.MethodPost, "/api/auth/logout", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("logout: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// The session row should be gone.
	if _, err := ts.store.GetSession(cookie.Value); err == nil {
		t.Errorf("expected session to be deleted, but still found")
	}

	// A Set-Cookie with MaxAge<0 must be emitted.
	found := false

	for _, c := range w.Result().Cookies() {
		if c.Name == auth.SessionCookieName && c.MaxAge < 0 {
			found = true

			break
		}
	}

	if !found {
		t.Errorf("expected a Set-Cookie clearing the session, got none")
	}
}

// -----------------------------------------------------------------------------
// Password change tests
// -----------------------------------------------------------------------------

func TestPasswordChange_WrongCurrentReturns401(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	cookie := ts.login("alice", "correcthorsebattery")

	w := ts.do(http.MethodPost, "/api/auth/password",
		passwordRequest{
			CurrentPassword: "wrong!",
			NewPassword:     "newpasswordvalid",
		}, cookie)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPasswordChange_SuccessRotatesSessionsButKeepsCurrent(t *testing.T) {
	ts := newTestServer(t)
	user := ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	// Create a second "other-device" session the password change should
	// invalidate.
	otherSess, err := ts.store.CreateSession(user.ID)
	if err != nil {
		t.Fatalf("seed other session: %v", err)
	}

	cookie := ts.login("alice", "correcthorsebattery")

	w := ts.do(http.MethodPost, "/api/auth/password",
		passwordRequest{
			CurrentPassword: "correcthorsebattery",
			NewPassword:     "newpasswordvalid",
		}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// The "other device" session must be gone.
	if _, err := ts.store.GetSession(otherSess.ID); err == nil {
		t.Errorf("other session should be invalidated by ResetPassword")
	}

	// The original request's cookie is also gone (ResetPassword deletes all
	// sessions), but a fresh session cookie must have been emitted.
	newCookie := sessionCookieFromResponse(t, w)
	if newCookie.Value == cookie.Value {
		t.Errorf("expected a new session token, got the same one")
	}

	if _, err := ts.store.GetSession(newCookie.Value); err != nil {
		t.Errorf("new session should exist: %v", err)
	}

	// New password works for subsequent login.
	w2 := ts.do(http.MethodPost, "/api/auth/login",
		loginRequest{Username: "alice", Password: "newpasswordvalid"})
	if w2.Code != http.StatusOK {
		t.Fatalf("login with new password: expected 200, got %d", w2.Code)
	}
}

// -----------------------------------------------------------------------------
// User-management tests
// -----------------------------------------------------------------------------

func TestCreateUser_DuplicateUsername(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.seedUser("admin", "correcthorsebattery", auth.RoleAdmin)
	ts.seedUser("existing", "correcthorsebattery", auth.RoleViewer)

	cookie := ts.login(admin.Username, "correcthorsebattery")

	w := ts.do(http.MethodPost, "/api/auth/users",
		createUserRequest{
			Username: "existing",
			Password: "correcthorsebattery",
			Role:     auth.RoleViewer,
		}, cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Error string `json:"error"`
	}

	mustDecode(t, w, &resp)

	if resp.Error != "username_taken" {
		t.Errorf("expected error username_taken, got %q", resp.Error)
	}
}

func TestCreateUser_Success(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.seedUser("admin", "correcthorsebattery", auth.RoleAdmin)

	cookie := ts.login(admin.Username, "correcthorsebattery")

	w := ts.do(http.MethodPost, "/api/auth/users",
		createUserRequest{
			Username: "bob",
			Password: "correcthorsebattery",
			Role:     auth.RoleViewer,
		}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data userResponse `json:"data"`
	}

	mustDecode(t, w, &resp)

	if resp.Data.Username != "bob" {
		t.Errorf("expected username bob, got %q", resp.Data.Username)
	}
}

func TestCreateUser_ViewerForbidden(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("admin", "correcthorsebattery", auth.RoleAdmin)
	ts.seedUser("viewer", "correcthorsebattery", auth.RoleViewer)

	cookie := ts.login("viewer", "correcthorsebattery")

	w := ts.do(http.MethodPost, "/api/auth/users",
		createUserRequest{
			Username: "bob",
			Password: "correcthorsebattery",
			Role:     auth.RoleViewer,
		}, cookie)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteUser_Self(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.seedUser("admin", "correcthorsebattery", auth.RoleAdmin)
	// Need a second admin so the last-admin check doesn't fire first.
	ts.seedUser("admin2", "correcthorsebattery", auth.RoleAdmin)

	cookie := ts.login(admin.Username, "correcthorsebattery")

	w := ts.do(http.MethodDelete, fmt.Sprintf("/api/auth/users/%d", admin.ID),
		nil, cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Error string `json:"error"`
	}

	mustDecode(t, w, &resp)

	if resp.Error != "cannot_delete_self" {
		t.Errorf("expected error cannot_delete_self, got %q", resp.Error)
	}
}

func TestDeleteUser_OtherUserSucceeds(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.seedUser("admin", "correcthorsebattery", auth.RoleAdmin)
	viewer := ts.seedUser("viewer", "correcthorsebattery", auth.RoleViewer)

	cookie := ts.login(admin.Username, "correcthorsebattery")

	w := ts.do(http.MethodDelete, fmt.Sprintf("/api/auth/users/%d", viewer.ID),
		nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if _, err := ts.store.GetUser(viewer.ID); err == nil {
		t.Errorf("expected viewer to be deleted, still found")
	}
}

// TestDeleteUser_LastAdminTranslation verifies the handler translates
// configstore's last-admin error to 409 last_admin. The scenario where this
// 409 fires is structurally narrow:
//
//   - RequireRole(admin) gates the DELETE route, so only admins can reach it.
//   - If there are N>=2 admins, deleting any one leaves N-1 >= 1, so the
//     configstore's refusal only fires when the deleter IS the last admin
//     deleting themselves — which is blocked first by the cannot_delete_self
//     guard in the handler.
//
// So to exercise the translation path we invoke the store directly here
// (matching the guard the handler uses) and confirm the error message shape
// the handler matches on.
func TestDeleteUser_LastAdminTranslation(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.seedUser("admin", "correcthorsebattery", auth.RoleAdmin)

	err := ts.store.DeleteUser(admin.ID)
	if err == nil {
		t.Fatalf("expected configstore to refuse last-admin delete, got nil")
	}

	if !strings.Contains(err.Error(), "last admin") {
		t.Fatalf("expected 'last admin' in error, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// CSRF / auth-required tests for authenticated endpoints
// -----------------------------------------------------------------------------

func TestAuthenticatedEndpoint_RequiresCookie(t *testing.T) {
	ts := newTestServer(t)
	ts.seedUser("alice", "correcthorsebattery", auth.RoleAdmin)

	w := ts.do(http.MethodPost, "/api/auth/logout", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without cookie, got %d", w.Code)
	}
}

// -----------------------------------------------------------------------------
// Rate limiter unit tests
// -----------------------------------------------------------------------------

func TestLoginLimiter_RefillsOverTime(t *testing.T) {
	l := &loginLimiter{now: time.Now}

	// Drain the bucket.
	for i := range loginBucketCap {
		ok, _ := l.allow("1.2.3.4")
		if !ok {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}

	// Next must be denied.
	ok, retry := l.allow("1.2.3.4")
	if ok {
		t.Errorf("expected denial after full drain")
	}

	if retry < 1 {
		t.Errorf("expected retry-after >= 1, got %d", retry)
	}

	// Fast-forward the clock. Refill for a full window gives back 5 tokens.
	future := time.Now().Add(loginBucketWindow + time.Second)
	l.now = func() time.Time { return future }

	ok, _ = l.allow("1.2.3.4")
	if !ok {
		t.Errorf("expected refill after a full window")
	}
}

func TestLoginLimiter_PrunesStaleEntries(t *testing.T) {
	l := &loginLimiter{now: time.Now}

	// Drain.
	for range loginBucketCap {
		l.allow("1.2.3.4")
	}

	// Jump past the prune threshold. Entry should reset to full capacity.
	future := time.Now().Add(loginBucketExpire + time.Minute)
	l.now = func() time.Time { return future }

	for i := range loginBucketCap {
		ok, _ := l.allow("1.2.3.4")
		if !ok {
			t.Errorf("post-prune attempt %d should be allowed", i+1)
		}
	}
}

// -----------------------------------------------------------------------------
// Client IP extraction tests
// -----------------------------------------------------------------------------

func TestClientIP_TrustedProxy(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.5:12345" // RFC1918 peer => trusted
	r.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.1")

	got := clientIP(r)
	if got != "203.0.113.1" {
		t.Errorf("expected 203.0.113.1, got %q", got)
	}
}

func TestClientIP_UntrustedPeerIgnoresXFF(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "8.8.8.8:12345" // public peer => not trusted
	r.Header.Set("X-Forwarded-For", "203.0.113.1")

	got := clientIP(r)
	if got != "8.8.8.8" {
		t.Errorf("expected 8.8.8.8, got %q", got)
	}
}

func TestClientIP_LoopbackTrusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "198.51.100.5")

	got := clientIP(r)
	if got != "198.51.100.5" {
		t.Errorf("expected 198.51.100.5, got %q", got)
	}
}
