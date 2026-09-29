// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/auth/authmodels"
)

// ctxKey is an unexported type used as a context key. Using distinct typed
// keys (rather than a string) prevents cross-package collisions.
type ctxKey int

const (
	userKey ctxKey = iota
	sessionKey
)

// SessionStore is the narrow interface the auth middleware depends on.
// *configstore.ConfigStore satisfies it as-is. Keeping it small makes the
// middleware trivial to test with an in-memory fake.
type SessionStore interface {
	HasUsers() bool
	GetSession(id string) (*authmodels.Session, error)
	GetUser(id uint) (*authmodels.User, error)
	ExtendSession(id string, newExpiry time.Time) error
	SessionRevoked() <-chan uint
}

// UserFromContext returns the authenticated user, or nil if no user was
// attached by RequireAuth.
func UserFromContext(ctx context.Context) *authmodels.User {
	u, _ := ctx.Value(userKey).(*authmodels.User)

	return u
}

// SessionFromContext returns the current request's session, or nil if no
// session was attached by RequireAuth. Downstream code (e.g., the WebSocket
// lifetime cap) uses the session's ExpiresAt to avoid double-extending an
// already-open socket beyond the true session expiry.
func SessionFromContext(ctx context.Context) *authmodels.Session {
	s, _ := ctx.Value(sessionKey).(*authmodels.Session)

	return s
}

// writeJSONError emits the {"error":..., "message":...} envelope used by
// every auth error response. Matches the Phase 4 plan contract.
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

// isAPIPath reports whether the request targets the JSON API surface.
func isAPIPath(p string) bool {
	return strings.HasPrefix(p, "/api/")
}

// isDocsPath reports whether the request targets the generated API docs
// surface — /docs/openapi.yaml and /docs/config.schema.json. Those describe the
// admin API and its configuration; nothing in the login flow needs them, so
// they are gated rather than public (owner decision D7, docs/UPSTREAM_SYNC.md).
func isDocsPath(p string) bool {
	return strings.HasPrefix(p, "/docs/")
}

// EnforcesAuth reports whether RequireAuth rejects an unauthenticated request to
// the given path. It is true for /api/* and /docs/*; every other path passes
// through so the SPA shell can render and detect auth state via
// /api/auth/session — so RequireAuth sitting on such a route's middleware chain
// is registration, not enforcement.
//
// The SPA shell, its static assets and /robots.txt must stay outside this
// predicate: gating them serves a 401 in place of the login page.
//
// Exported rather than inlined because server/api_contract_test.go annotates the
// route golden from it: a hand-maintained copy of this predicate would drift and
// the golden would go back to over-reading as protection (GRA-647).
func EnforcesAuth(path string) bool {
	return isAPIPath(path) || isDocsPath(path)
}

// IsSecureRequest reports whether the incoming request is on a secure origin.
// Used to pick between SessionCookieName and SessionCookieNameSecure when
// emitting Set-Cookie.
func IsSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}

	if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}

	return false
}

// ReadSessionCookie returns the session cookie value and the cookie name
// that carried it. Prefers the __Host- secure cookie when both are present.
// Returns ("", "") when no session cookie is set.
func ReadSessionCookie(r *http.Request) (value, name string) {
	if c, err := r.Cookie(SessionCookieNameSecure); err == nil && c.Value != "" {
		return c.Value, SessionCookieNameSecure
	}

	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		return c.Value, SessionCookieName
	}

	return "", ""
}

// RequireAuth enforces authentication on the request. Behavior:
//
//   - No users configured: POST /api/auth/setup passes through; other guarded
//     paths (EnforcesAuth) receive 401 setup_required; the rest pass through so
//     the SPA can render the setup wizard.
//   - Valid session: user is attached to context; sliding renewal applied
//     when expiry is within SessionSlidingThreshold.
//   - Missing/invalid/expired: 401 unauthorized on guarded paths, pass through
//     elsewhere (SPA detects state via /api/auth/session).
func RequireAuth(store SessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// First-run: no users. Setup endpoint is the only door open.
			if !store.HasUsers() {
				if EnforcesAuth(r.URL.Path) {
					if r.Method == http.MethodPost && r.URL.Path == "/api/auth/setup" {
						next.ServeHTTP(w, r)

						return
					}

					writeJSONError(w, http.StatusUnauthorized,
						"setup_required", "no users configured")

					return
				}

				// Ungated: SPA loads, discovers setup state, shows wizard.
				next.ServeHTTP(w, r)

				return
			}

			token, cookieName := ReadSessionCookie(r)
			if token == "" {
				if EnforcesAuth(r.URL.Path) {
					writeJSONError(w, http.StatusUnauthorized,
						"unauthorized", "authentication required")

					return
				}

				next.ServeHTTP(w, r)

				return
			}

			sess, err := store.GetSession(token)
			if err != nil || sess == nil {
				if EnforcesAuth(r.URL.Path) {
					writeJSONError(w, http.StatusUnauthorized,
						"unauthorized", "authentication required")

					return
				}

				next.ServeHTTP(w, r)

				return
			}

			user, err := store.GetUser(sess.UserID)
			if err != nil || user == nil {
				if EnforcesAuth(r.URL.Path) {
					writeJSONError(w, http.StatusUnauthorized,
						"unauthorized", "authentication required")

					return
				}

				next.ServeHTTP(w, r)

				return
			}

			// Sliding renewal. ExtendSession is conditionally idempotent
			// (Phase 1); calling it unconditionally here is safe.
			if time.Until(sess.ExpiresAt) < SessionSlidingThreshold {
				newExpiry := time.Now().Add(SessionDuration)
				if err := store.ExtendSession(sess.ID, newExpiry); err == nil {
					// Mirror the stored row so downstream SessionFromContext
					// consumers see the extended expiry.
					sess.ExpiresAt = newExpiry

					// Rewrite the cookie under the same name it arrived on
					// so the secure/insecure invariants don't flip mid-session.
					secure := IsSecureRequest(r)
					if cookieName == "" {
						cookieName = SessionCookieName
						if secure {
							cookieName = SessionCookieNameSecure
						}
					}

					http.SetCookie(w, &http.Cookie{
						Name:     cookieName,
						Value:    sess.ID,
						Path:     "/",
						MaxAge:   int(SessionDuration.Seconds()),
						HttpOnly: true,
						SameSite: http.SameSiteLaxMode,
						Secure:   secure || cookieName == SessionCookieNameSecure,
					})
				}
			}

			ctx := context.WithValue(r.Context(), userKey, user)
			ctx = context.WithValue(ctx, sessionKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns middleware that 403s unless the authenticated user
// has the exact given role.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil || user.Role != role {
				writeJSONError(w, http.StatusForbidden,
					"forbidden", "admin role required")

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdminForMutations lets GET/HEAD/OPTIONS through for any
// authenticated role and requires RoleAdmin for POST/PUT/DELETE/PATCH.
func RequireAdminForMutations() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)

				return
			}

			user := UserFromContext(r.Context())
			if user == nil || user.Role != RoleAdmin {
				writeJSONError(w, http.StatusForbidden,
					"forbidden", "admin role required for modifications")

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireCSRFHeader rejects mutation requests that lack a non-empty
// X-Requested-With header. Browsers will not add custom headers to
// cross-origin form POSTs, so the header's presence is a sufficient
// signal that the request came from the SPA fetch path.
func RequireCSRFHeader() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)

				return
			}

			if r.Header.Get("X-Requested-With") == "" {
				writeJSONError(w, http.StatusForbidden,
					"forbidden", "missing X-Requested-With header")

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
