// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0xERR0R/blocky/auth"
	"github.com/0xERR0R/blocky/configstore"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
)

// -----------------------------------------------------------------------------
// JSON envelope + helpers
// -----------------------------------------------------------------------------

// writeAuthJSONError emits the {"error":..., "message":...} envelope used by
// every auth endpoint on a failure path.
func writeAuthJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

// writeAuthJSONData wraps the happy-path `{"data": ...}` envelope.
func writeAuthJSONData(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

// writeAuthJSONMessage wraps the happy-path `{"message": ...}` envelope.
func writeAuthJSONMessage(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

// decodeBody reads and decodes a JSON body into dst, rejecting oversized or
// malformed inputs with a 400.
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	const maxBody = 1 << 15 // 32 KiB is plenty for any auth payload

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		writeAuthJSONError(w, http.StatusBadRequest,
			"invalid_request", "invalid JSON body: "+err.Error())

		return false
	}

	return true
}

// -----------------------------------------------------------------------------
// Cookie helpers
// -----------------------------------------------------------------------------

// sessionCookieNameFor picks the __Host-prefixed name over HTTPS and the plain
// name over HTTP. The middleware reads whichever is present.
func sessionCookieNameFor(r *http.Request) string {
	if auth.IsSecureRequest(r) {
		return auth.SessionCookieNameSecure
	}

	return auth.SessionCookieName
}

// buildSessionCookie produces a Set-Cookie with the correct name + attributes
// for the request's origin. Pass maxAge = SessionDuration seconds for a live
// cookie, or maxAge = -1 to clear.
func buildSessionCookie(r *http.Request, token string, maxAge int) *http.Cookie {
	name := sessionCookieNameFor(r)
	secure := auth.IsSecureRequest(r)

	return &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// __Host- prefix requires Secure=true. Over plain HTTP we use the
		// regular name and must not set Secure — a plain-HTTP response that
		// tries to Set-Cookie with Secure=true is silently dropped.
		Secure: secure || name == auth.SessionCookieNameSecure,
	}
}

// -----------------------------------------------------------------------------
// Rate limiter (token bucket, per-IP, lazy pruning)
// -----------------------------------------------------------------------------

const (
	loginBucketCap    = 5
	loginBucketWindow = time.Minute      // full refill window
	loginBucketExpire = 10 * time.Minute // prune entries idle this long
)

type loginBucket struct {
	mu          sync.Mutex
	tokens      float64
	lastAttempt time.Time
}

// loginLimiter is a per-IP token-bucket rate limiter. 5 tokens / min. A fresh
// IP gets a full bucket on first hit. Tokens refill linearly over the window.
// Entries idle for 10 minutes get pruned lazily on access.
type loginLimiter struct {
	buckets sync.Map // map[string]*loginBucket
	now     func() time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{now: time.Now}
}

// allow reports whether a login attempt from ip is permitted and, if not,
// returns the number of seconds the client should wait before retrying.
func (l *loginLimiter) allow(ip string) (ok bool, retryAfter int) {
	now := l.now()

	v, _ := l.buckets.LoadOrStore(ip, &loginBucket{tokens: loginBucketCap, lastAttempt: now})
	b := v.(*loginBucket)

	b.mu.Lock()
	defer b.mu.Unlock()

	elapsed := now.Sub(b.lastAttempt)

	// Prune-on-access: if the entry is ancient, reset to full. (A background
	// goroutine would also work; lazy pruning keeps the code self-contained.)
	if elapsed > loginBucketExpire {
		b.tokens = loginBucketCap
		b.lastAttempt = now
		elapsed = 0
	}

	// Refill proportional to elapsed time, capped at one full window.
	if elapsed > loginBucketWindow {
		elapsed = loginBucketWindow
	}

	b.tokens += float64(elapsed) / float64(loginBucketWindow) * float64(loginBucketCap)
	if b.tokens > loginBucketCap {
		b.tokens = loginBucketCap
	}

	b.lastAttempt = now

	if b.tokens >= 1 {
		b.tokens--

		return true, 0
	}

	// No token available — compute seconds until the next one arrives.
	need := 1 - b.tokens
	secs := max(int((need*float64(loginBucketWindow))/float64(loginBucketCap)/float64(time.Second)), 1)

	return false, secs
}

// reset drops any tracked state for ip so a successful login restores a full
// bucket. Matches the common UX where successful auth wipes the failure counter.
func (l *loginLimiter) reset(ip string) {
	l.buckets.Delete(ip)
}

// -----------------------------------------------------------------------------
// Client IP extraction
// -----------------------------------------------------------------------------

// trustedProxyNets are the CIDRs we consider "trusted proxy" peers when no
// explicit trusted_proxies config is set. A direct peer on loopback or RFC1918
// space is treated as a trusted reverse proxy whose X-Forwarded-For header is
// worth honoring. Over the public internet we fall back to r.RemoteAddr, which
// cannot be spoofed.
//
// This is a pragmatic default; a future trusted_proxies config option can
// replace the hard-coded CIDR list.
var trustedProxyNets = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",  // IPv6 ULA
		"fe80::/10", // IPv6 link-local
	}

	nets := make([]*net.IPNet, 0, len(cidrs))

	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}

		nets = append(nets, n)
	}

	return nets
}()

// clientIP returns the effective client IP for rate-limiting purposes. When
// the direct peer is on a trusted-proxy CIDR, the leftmost X-Forwarded-For
// entry is honored. Otherwise the raw RemoteAddr is used (which cannot be
// spoofed by an unprivileged client).
func clientIP(r *http.Request) string {
	peerIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerIP = r.RemoteAddr
	}

	if isTrustedProxy(peerIP) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Leftmost entry is the original client per RFC 7239 convention.
			first, _, _ := strings.Cut(xff, ",")

			return strings.TrimSpace(first)
		}
	}

	return peerIP
}

func isTrustedProxy(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// -----------------------------------------------------------------------------
// Handler struct
// -----------------------------------------------------------------------------

// authHandler bundles the dependencies the auth endpoints need. It is
// instantiated once per server and provides RegisterPublicRoutes /
// RegisterAuthenticatedRoutes as the mount shape Phase 5 uses.
type authHandler struct {
	store   *configstore.ConfigStore
	limiter *loginLimiter

	// dummyHash is a fixed bcrypt hash used by the login handler to spend
	// CPU on the "user not found" path so the response time matches the
	// "user found, wrong password" path. Prevents a username-enumeration
	// timing side channel.
	dummyHash string
}

func newAuthHandler(store *configstore.ConfigStore) *authHandler {
	// Generate a throwaway bcrypt hash at construction time. bcrypt.DefaultCost
	// runs once here (~60ms) and is then reused for every failed-lookup path.
	dh, err := auth.HashPassword("dummy-password-for-timing-balance")
	if err != nil {
		// HashPassword only fails on empty input. Unreachable in practice;
		// a zero hash just makes the timing balance slightly worse.
		dh = ""
	}

	return &authHandler{
		store:     store,
		limiter:   newLoginLimiter(),
		dummyHash: dh,
	}
}

// RegisterPublicRoutes mounts the routes that do not require a valid session
// (login, setup). Both are CSRF-guarded internally so the caller doesn't have
// to remember to wrap them.
func (h *authHandler) RegisterPublicRoutes(r chi.Router) {
	r.Group(func(g chi.Router) {
		g.Use(auth.RequireCSRFHeader())

		g.Post("/api/auth/login", h.handleLogin)
		g.Post("/api/auth/setup", h.handleSetup)
	})
}

// RegisterAuthenticatedRoutes mounts the session-protected auth endpoints.
// The caller MUST wrap r with auth.RequireAuth before calling this. Phase 5
// also applies auth.RequireCSRFHeader at the whole authenticated-group level,
// so we do not re-apply it here.
//
// /api/auth/session is mounted here (not in the public group) because the
// "not logged in" branches are fully handled by RequireAuth — it returns
// setup_required when no users exist and unauthorized otherwise. The handler
// in this file only runs on the happy path and returns the current user.
func (h *authHandler) RegisterAuthenticatedRoutes(r chi.Router) {
	r.Get("/api/auth/session", h.handleSession)
	r.Post("/api/auth/logout", h.handleLogout)
	r.Post("/api/auth/password", h.handlePasswordChange)

	r.Group(func(admin chi.Router) {
		admin.Use(auth.RequireRole(auth.RoleAdmin))

		admin.Get("/api/auth/users", h.handleListUsers)
		admin.Post("/api/auth/users", h.handleCreateUser)
		admin.Delete("/api/auth/users/{id}", h.handleDeleteUser)
	})
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type userResponse struct {
	ID        uint      `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func userToResponse(u *configstore.User) userResponse {
	return userResponse{
		ID:        u.ID,
		Username:  u.Username,
		Role:      u.Role,
		CreatedAt: u.CreatedAt,
	}
}

func (h *authHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	if ok, retry := h.limiter.allow(ip); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeAuthJSONError(w, http.StatusTooManyRequests,
			"rate_limited", "too many login attempts, try again later")

		return
	}

	var req loginRequest
	if !decodeBody(w, r, &req) {
		return
	}

	username := strings.ToLower(strings.TrimSpace(req.Username))

	// Never trust an incoming session cookie. We always mint a fresh token
	// after a successful password compare, overwriting whatever the client
	// sent.

	user, err := h.store.GetUserByUsername(username)
	if err != nil || user == nil {
		// Spend CPU on a dummy compare so the failed-lookup path takes the
		// same wall time as the found-but-wrong-password path.
		_ = auth.CheckPassword(h.dummyHash, req.Password)

		writeAuthJSONError(w, http.StatusUnauthorized,
			"invalid_credentials", "invalid username or password")

		return
	}

	if !auth.CheckPassword(user.PasswordHash, req.Password) {
		writeAuthJSONError(w, http.StatusUnauthorized,
			"invalid_credentials", "invalid username or password")

		return
	}

	sess, err := h.store.CreateSession(user.ID)
	if err != nil {
		writeAuthJSONError(w, http.StatusInternalServerError,
			"session_error", "failed to create session")

		return
	}

	http.SetCookie(w, buildSessionCookie(r, sess.ID, int(auth.SessionDuration.Seconds())))

	// Successful login resets the rate-limit bucket for this IP.
	h.limiter.reset(ip)

	writeAuthJSONData(w, http.StatusOK, userToResponse(user))
}

func (h *authHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Read whichever cookie carried the session and delete it server-side.
	token, _ := auth.ReadSessionCookie(r)
	if token != "" {
		if err := h.store.DeleteSession(token); err != nil {
			// Best-effort logout: log and still clear the cookie so the
			// client can't reuse it. Worst case is a stale DB row that the
			// hourly prune cleans up later.
			logger().WithError(err).Warn("delete session on logout failed")
		}
	}

	// Clear the cookie on both names so clients don't keep sending stale
	// values. MaxAge=-1 tells the browser to delete immediately.
	clearSessionCookies(w, r)

	writeAuthJSONMessage(w, http.StatusOK, "logged out")
}

func (h *authHandler) handleSession(w http.ResponseWriter, r *http.Request) {
	// RequireAuth gates this route, so we only reach this handler on the
	// happy path. The middleware already handles the "no users" and
	// "missing cookie" branches with the right envelope codes.
	user := auth.UserFromContext(r.Context())
	if user == nil {
		// Defensive: if RequireAuth is ever removed from the chain, fall
		// back to the right error rather than leaking an empty 200.
		if !h.store.HasUsers() {
			writeAuthJSONError(w, http.StatusUnauthorized,
				"setup_required", "no users configured")

			return
		}

		writeAuthJSONError(w, http.StatusUnauthorized,
			"unauthorized", "authentication required")

		return
	}

	writeAuthJSONData(w, http.StatusOK, userToResponse(user))
}

type setupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *authHandler) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	if !decodeBody(w, r, &req) {
		return
	}

	username := strings.ToLower(strings.TrimSpace(req.Username))
	if err := auth.ValidateUsername(username); err != nil {
		writeAuthJSONError(w, http.StatusBadRequest,
			"invalid_request", err.Error())

		return
	}

	if err := auth.ValidatePassword(req.Password); err != nil {
		writeAuthJSONError(w, http.StatusBadRequest,
			"invalid_request", err.Error())

		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeAuthJSONError(w, http.StatusInternalServerError,
			"hash_error", "failed to hash password")

		return
	}

	token, err := auth.GenerateSessionToken()
	if err != nil {
		writeAuthJSONError(w, http.StatusInternalServerError,
			"token_error", "failed to generate session token")

		return
	}

	now := time.Now().UTC()

	u := &configstore.User{
		Username:     username,
		PasswordHash: hash,
		Role:         auth.RoleAdmin,
	}

	sess := &configstore.Session{
		ID:        token,
		ExpiresAt: now.Add(auth.SessionDuration),
	}

	err = h.store.SetupFirstAdmin(r.Context(), u, sess)
	if err != nil {
		switch {
		case errors.Is(err, configstore.ErrSetupAlreadyDone):
			writeAuthJSONError(w, http.StatusConflict,
				"already_configured", "setup has already been completed")
		case errors.Is(err, gorm.ErrDuplicatedKey) || isUniqueConstraintErr(err):
			// Defense in depth: a unique violation here means another setup
			// beat us to the INSERT even though the COUNT said zero.
			writeAuthJSONError(w, http.StatusConflict,
				"already_configured", "setup has already been completed")
		default:
			logger().WithError(err).Warn("setup first admin failed")
			writeAuthJSONError(w, http.StatusInternalServerError,
				"tx_error", "failed to complete setup")
		}

		return
	}

	http.SetCookie(w, buildSessionCookie(r, token, int(auth.SessionDuration.Seconds())))

	writeAuthJSONData(w, http.StatusOK, userResponse{
		ID:        u.ID,
		Username:  u.Username,
		Role:      u.Role,
		CreatedAt: u.CreatedAt,
	})
}

type passwordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *authHandler) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeAuthJSONError(w, http.StatusUnauthorized,
			"unauthorized", "authentication required")

		return
	}

	var req passwordRequest
	if !decodeBody(w, r, &req) {
		return
	}

	// Re-verify current password. We pull a fresh user from the store so we
	// see the latest password_hash in case the context-attached user is stale.
	fresh, err := h.store.GetUser(user.ID)
	if err != nil || fresh == nil {
		writeAuthJSONError(w, http.StatusUnauthorized,
			"unauthorized", "authentication required")

		return
	}

	if !auth.CheckPassword(fresh.PasswordHash, req.CurrentPassword) {
		writeAuthJSONError(w, http.StatusUnauthorized,
			"invalid_credentials", "current password is incorrect")

		return
	}

	if err := auth.ValidatePassword(req.NewPassword); err != nil {
		writeAuthJSONError(w, http.StatusBadRequest,
			"invalid_request", err.Error())

		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeAuthJSONError(w, http.StatusInternalServerError,
			"hash_error", "failed to hash password")

		return
	}

	// ResetPassword updates the row AND calls DeleteSessionsForUser, which
	// publishes on SessionRevoked. The current request's session has now
	// been deleted — mint a new one for this device so the user stays
	// logged in here but is signed out everywhere else.
	//
	// If session invalidation failed, DO NOT mint a new session: the old
	// sessions may still be live and the user has no way to know their
	// credential change did not actually force a re-login elsewhere.
	if err := h.store.ResetPassword(user.ID, newHash); err != nil {
		logger().WithError(err).Warn("reset password failed")
		writeAuthJSONError(w, http.StatusInternalServerError,
			"password_error", "failed to update password")

		return
	}

	sess, err := h.store.CreateSession(user.ID)
	if err != nil {
		writeAuthJSONError(w, http.StatusInternalServerError,
			"session_error", "failed to create new session")

		return
	}

	http.SetCookie(w, buildSessionCookie(r, sess.ID, int(auth.SessionDuration.Seconds())))

	writeAuthJSONMessage(w, http.StatusOK, "password updated")
}

func (h *authHandler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers()
	if err != nil {
		writeAuthJSONError(w, http.StatusInternalServerError,
			"query_error", "failed to list users")

		return
	}

	out := make([]userResponse, 0, len(users))
	for i := range users {
		out = append(out, userToResponse(&users[i]))
	}

	writeAuthJSONData(w, http.StatusOK, out)
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (h *authHandler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if !decodeBody(w, r, &req) {
		return
	}

	username := strings.ToLower(strings.TrimSpace(req.Username))
	if err := auth.ValidateUsername(username); err != nil {
		writeAuthJSONError(w, http.StatusBadRequest,
			"invalid_request", err.Error())

		return
	}

	if err := auth.ValidateRole(req.Role); err != nil {
		writeAuthJSONError(w, http.StatusBadRequest,
			"invalid_request", err.Error())

		return
	}

	if err := auth.ValidatePassword(req.Password); err != nil {
		writeAuthJSONError(w, http.StatusBadRequest,
			"invalid_request", err.Error())

		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeAuthJSONError(w, http.StatusInternalServerError,
			"hash_error", "failed to hash password")

		return
	}

	u := &configstore.User{
		Username:     username,
		PasswordHash: hash,
		Role:         req.Role,
	}

	if err := h.store.CreateUser(u); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || isUniqueConstraintErr(err) {
			writeAuthJSONError(w, http.StatusConflict,
				"username_taken", "username already exists")

			return
		}

		writeAuthJSONError(w, http.StatusInternalServerError,
			"create_error", "failed to create user")

		return
	}

	writeAuthJSONData(w, http.StatusCreated, userToResponse(u))
}

func (h *authHandler) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	actor := auth.UserFromContext(r.Context())
	if actor == nil {
		writeAuthJSONError(w, http.StatusUnauthorized,
			"unauthorized", "authentication required")

		return
	}

	idStr := chi.URLParam(r, "id")

	id64, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		writeAuthJSONError(w, http.StatusBadRequest,
			"invalid_request", "invalid user id")

		return
	}

	id := uint(id64)

	if id == actor.ID {
		writeAuthJSONError(w, http.StatusConflict,
			"cannot_delete_self", "cannot delete your own account")

		return
	}

	if err := h.store.DeleteUser(id); err != nil {
		if errors.Is(err, configstore.ErrLastAdmin) {
			writeAuthJSONError(w, http.StatusConflict,
				"last_admin", "cannot delete the last admin")

			return
		}

		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeAuthJSONError(w, http.StatusNotFound,
				"not_found", "user not found")

			return
		}

		writeAuthJSONError(w, http.StatusInternalServerError,
			"delete_error", "failed to delete user")

		return
	}

	writeAuthJSONMessage(w, http.StatusOK, "user deleted")
}

// -----------------------------------------------------------------------------
// Helpers local to this file
// -----------------------------------------------------------------------------

// clearSessionCookies emits Set-Cookie headers that delete whichever session
// cookies might be set on this origin. We clear both names to be safe — a
// cookie that persists after logout would be a real security issue.
func clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	secure := auth.IsSecureRequest(r)

	// Always clear the plain name. Do not set Secure=true over plain HTTP,
	// or the browser will reject the Set-Cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
	})

	// Only clear __Host- when we can legitimately emit a Secure cookie;
	// __Host- requires Secure=true and Path=/.
	if secure {
		http.SetCookie(w, &http.Cookie{
			Name:     auth.SessionCookieNameSecure,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   true,
		})
	}
}

// isUniqueConstraintErr matches SQLite's UNIQUE-constraint error message as
// a fallback when GORM's error-translator isn't enabled (the existing
// configstore does not set gorm.Config.TranslateError=true, so we need this).
func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}

	msg := err.Error()

	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed: UNIQUE")
}

// -----------------------------------------------------------------------------
// Phase-5 wiring helpers
// -----------------------------------------------------------------------------

// registerAuthRoutes mounts the publicly-reachable auth endpoints (login,
// setup, session-probe). Phase 5 invokes this from registerUIRoutes.
//
// Login and setup are guarded by RequireCSRFHeader (applied internally).
// Session is a read-only probe and is intentionally header-agnostic.
func registerAuthRoutes(router chi.Router, store *configstore.ConfigStore) {
	h := newAuthHandler(store)
	h.RegisterPublicRoutes(router)
}

// registerAuthenticatedAuthRoutes mounts the session-protected auth endpoints.
// The caller must have already applied auth.RequireAuth. Phase 5 also applies
// auth.RequireCSRFHeader at the authenticated-group level, so it is not
// re-applied here.
func registerAuthenticatedAuthRoutes(router chi.Router, store *configstore.ConfigStore) {
	h := newAuthHandler(store)
	h.RegisterAuthenticatedRoutes(router)
}
