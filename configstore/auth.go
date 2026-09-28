// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package configstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/auth"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// ErrLastAdmin is returned by DeleteUser when the caller tries to remove the
// only remaining admin account. Callers should use errors.Is to detect it.
var ErrLastAdmin = errors.New("cannot delete the last admin user")

const (
	// hasUsersColdTTL bounds how often HasUsers re-queries the DB while the
	// cache is still false. A separate PID (CLI `user create`) may have seeded
	// users after the server started; this TTL lets the server notice without
	// a file watcher or signal.
	hasUsersColdTTL = 5 * time.Second
)

// normalizeUsername folds usernames for case-insensitive uniqueness.
// Policy (Phase 1): usernames are stored and compared lower-cased. All
// CreateUser / GetUserByUsername callers normalize through this helper.
func normalizeUsername(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}

// HasUsers reports whether any users exist. Cache-first; while the cache
// is still false, re-queries the DB at most once every hasUsersColdTTL.
// Once the cache flips true it never flips back within a process lifetime
// via this path — DeleteUser has its own refresh that can drive it false.
func (s *ConfigStore) HasUsers() bool {
	if s.hasUsersCache.Load() {
		return true
	}

	// Cold path: possibly stale false. Rate-limit the re-query.
	now := time.Now().UnixNano()
	last := s.hasUsersLastCheck.Load()

	if now-last < int64(hasUsersColdTTL) {
		return false
	}

	s.hasUsersLastCheck.Store(now)

	var count int64
	s.roDB.Model(&User{}).Count(&count)

	if count > 0 {
		s.hasUsersCache.Store(true)

		return true
	}

	return false
}

// refreshHasUsersCache re-queries the DB and updates the atomic cache.
// Called by CreateUser (flips true) and DeleteUser (may flip false if the
// last user was removed). Uses roDB so it does not contend with the
// serialized write connection.
func (s *ConfigStore) refreshHasUsersCache() {
	var count int64
	s.roDB.Model(&User{}).Count(&count)
	s.hasUsersCache.Store(count > 0)
}

// SessionRevoked returns a read-only channel that emits the userID of any
// user whose sessions were just invalidated. Consumers (e.g., the WebSocket
// log broadcaster in server/) subscribe to this to close active sockets.
// The underlying channel is buffered (16) so auth write paths never block;
// a slow consumer simply drops signals on the floor.
func (s *ConfigStore) SessionRevoked() <-chan uint {
	return s.sessionRevoked
}

// ListUsers returns all users ordered by username.
func (s *ConfigStore) ListUsers() ([]User, error) {
	var users []User
	if err := s.roDB.Order("username").Find(&users).Error; err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	return users, nil
}

// GetUser returns a user by ID.
func (s *ConfigStore) GetUser(id uint) (*User, error) {
	var u User
	if err := s.roDB.First(&u, id).Error; err != nil {
		return nil, fmt.Errorf("get user %d: %w", id, err)
	}

	return &u, nil
}

// GetUserByUsername returns a user by username (case-insensitive match).
func (s *ConfigStore) GetUserByUsername(username string) (*User, error) {
	var u User

	normalized := normalizeUsername(username)

	if err := s.roDB.Where("LOWER(username) = ?", normalized).First(&u).Error; err != nil {
		return nil, fmt.Errorf("get user %q: %w", username, err)
	}

	return &u, nil
}

// CreateUser persists a new user. Username is normalized to lower-case
// before insert so the unique index enforces case-insensitive uniqueness.
func (s *ConfigStore) CreateUser(u *User) error {
	u.Username = normalizeUsername(u.Username)

	if err := s.db.Create(u).Error; err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	s.refreshHasUsersCache()

	return nil
}

// DeleteUser removes a user by ID. Invariants:
//   - refuses to delete the last admin (returns ErrLastAdmin)
//   - invalidates all sessions for the user atomically with the user delete
//   - refreshes the hasUsers cache after the row delete
//
// The admin-count check, session delete, and user delete all run inside a
// single BEGIN IMMEDIATE transaction so two concurrent callers trying to
// remove different admins cannot both pass the "more than one admin remains"
// guard and leave zero admins. SQLite's write lock serializes the callers at
// BEGIN; the loser sees the committed delete and its own guard then fails.
func (s *ConfigStore) DeleteUser(id uint) error {
	u, err := s.GetUser(id)
	if err != nil {
		return err
	}

	ctx := context.Background()

	conn, err := s.BeginImmediate(ctx)
	if err != nil {
		return fmt.Errorf("delete user %d: begin tx: %w", id, err)
	}

	committed := false

	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}

		conn.Close()
	}()

	if u.Role == "admin" {
		var adminCount int64
		if err := conn.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&adminCount); err != nil {
			return fmt.Errorf("delete user %d: count admins: %w", id, err)
		}

		if adminCount <= 1 {
			return ErrLastAdmin
		}
	}

	// Sessions go first so an in-flight request cannot resurrect access
	// between the user delete and the session delete. Both run under the
	// same write lock, so the whole operation is atomic w.r.t. other writers.
	if _, err := conn.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		return fmt.Errorf("delete user %d: delete sessions: %w", id, err)
	}

	res, err := conn.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user %d: %w", id, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete user %d: rows affected: %w", id, err)
	}

	if affected == 0 {
		return gorm.ErrRecordNotFound
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("delete user %d: commit: %w", id, err)
	}

	committed = true

	// Publish revocation signal AFTER the commit so consumers can't observe
	// a revoked session still present in the DB during a retry.
	select {
	case s.sessionRevoked <- id:
	default:
	}

	s.refreshHasUsersCache()

	return nil
}

// CreateSession creates a new session with a 32-byte crypto/rand hex token
// and a 24h expiry.
func (s *ConfigStore) CreateSession(userID uint) (*Session, error) {
	token, err := auth.GenerateSessionToken()
	if err != nil {
		return nil, err
	}

	sess := &Session{
		ID:        token,
		UserID:    userID,
		ExpiresAt: time.Now().Add(auth.SessionDuration),
	}

	if err := s.db.Create(sess).Error; err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return sess, nil
}

// GetSession returns a non-expired session by ID. Returns the underlying
// gorm.ErrRecordNotFound if the session does not exist OR has expired;
// callers should not try to distinguish the two.
func (s *ConfigStore) GetSession(id string) (*Session, error) {
	var sess Session
	if err := s.roDB.Where("id = ? AND expires_at > ?", id, time.Now()).First(&sess).Error; err != nil {
		return nil, err
	}

	return &sess, nil
}

// ExtendSession conditionally pushes a session's expiry forward. Idempotent:
// the UPDATE only fires when the new expiry is later than the stored one, so
// concurrent renewals (multiple requests within the same moment) can't thrash
// the expires_at column backward.
func (s *ConfigStore) ExtendSession(id string, newExpiry time.Time) error {
	res := s.db.Model(&Session{}).
		Where("id = ? AND expires_at < ?", id, newExpiry).
		Update("expires_at", newExpiry)
	if res.Error != nil {
		return fmt.Errorf("extend session: %w", res.Error)
	}

	return nil
}

// DeleteSession removes a single session by ID. Returns an error if the DB
// delete fails; a missing row is NOT an error.
func (s *ConfigStore) DeleteSession(id string) error {
	if err := s.db.Where("id = ?", id).Delete(&Session{}).Error; err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}

// DeleteSessionsForUser removes every session owned by a user and publishes
// the userID on the revocation channel. The send is non-blocking: if the
// buffer is full (16 pending) we drop the signal rather than hold the auth
// write path hostage to a slow consumer. Returns an error if the DB delete
// fails — callers that invalidate sessions for security reasons (password
// change, user delete) MUST propagate this error rather than mint a new
// session on top of failed revocation.
func (s *ConfigStore) DeleteSessionsForUser(userID uint) error {
	if err := s.db.Where("user_id = ?", userID).Delete(&Session{}).Error; err != nil {
		return fmt.Errorf("delete sessions for user %d: %w", userID, err)
	}

	select {
	case s.sessionRevoked <- userID:
	default:
	}

	return nil
}

// PruneExpiredSessions removes sessions whose expires_at is in the past.
// Parameterized WHERE hits the expires_at index. Returns an error if the DB
// delete fails; callers (e.g., the hourly ticker) should log and continue.
func (s *ConfigStore) PruneExpiredSessions() error {
	if err := s.db.Where("expires_at < ?", time.Now()).Delete(&Session{}).Error; err != nil {
		return fmt.Errorf("prune expired sessions: %w", err)
	}

	return nil
}

// BeginImmediate acquires a pinned connection from the RW pool and issues
// `BEGIN IMMEDIATE` so the SQLite write lock is acquired at BEGIN rather than
// lazily on first write. This forces concurrent callers to serialize at the
// BEGIN and is required for correctness in the setup endpoint's
// read-check-insert window.
//
// The returned connection MUST have its lifecycle closed by the caller. The
// typical pattern is:
//
//	conn, err := store.BeginImmediate(ctx)
//	if err != nil { ... }
//	defer conn.Close() // returns the conn to the pool
//	// ... do work on conn ...
//	if rollback { conn.ExecContext(ctx, "ROLLBACK") } else {
//	    conn.ExecContext(ctx, "COMMIT")
//	}
//
// SQL statements issued on this conn use the database/sql layer directly;
// GORM is not involved inside the manual transaction. All writes on the RW
// pool serialize through the single pooled connection (MaxOpenConns=1) so
// this conn does not deadlock against other callers — they wait at the
// pool acquire instead.
func (s *ConfigStore) BeginImmediate(ctx context.Context) (*sql.Conn, error) {
	sqlDB, err := s.db.DB()
	if err != nil {
		return nil, fmt.Errorf("get underlying sql.DB: %w", err)
	}

	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection: %w", err)
	}

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		conn.Close()

		return nil, fmt.Errorf("begin immediate: %w", err)
	}

	return conn, nil
}

// SetupFirstAdmin atomically checks that no users exist and, on success,
// creates the admin user and its initial session inside a single
// BEGIN IMMEDIATE transaction. It is the race-safe replacement for the
// setup endpoint's hand-written INSERTs: callers pass GORM model pointers
// and the store handles the tx lifecycle and cache refresh.
//
// Returns:
//   - nil on success with u.ID and sess fields populated
//   - ErrSetupAlreadyDone if any user row already exists
//   - any DB error (wrapped) otherwise
//
// Username is normalized to lower-case before INSERT (matches CreateUser).
func (s *ConfigStore) SetupFirstAdmin(ctx context.Context, u *User, sess *Session) error {
	u.Username = normalizeUsername(u.Username)

	conn, err := s.BeginImmediate(ctx)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}

	// Rollback runs on any error path. COMMIT sets committed=true so the
	// defer skips the rollback. Using context.WithoutCancel so a cancelled
	// request context doesn't abandon the write lock.
	committed := false

	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}

		conn.Close()
	}()

	// Wrap the *sql.Conn as a GORM ConnPool so we can use the model layer
	// for INSERTs. This lets schema changes to User/Session propagate
	// automatically without hand-maintained column lists.
	txDB, err := gorm.Open(&sqlite.Dialector{Conn: conn}, &gorm.Config{
		Logger:                 s.db.Logger,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		return fmt.Errorf("setup: open gorm over conn: %w", err)
	}

	txDB = txDB.WithContext(ctx)

	var count int64
	if err := txDB.Model(&User{}).Count(&count).Error; err != nil {
		return fmt.Errorf("setup: count users: %w", err)
	}

	if count > 0 {
		return ErrSetupAlreadyDone
	}

	if err := txDB.Create(u).Error; err != nil {
		return fmt.Errorf("setup: create user: %w", err)
	}

	sess.UserID = u.ID

	if err := txDB.Create(sess).Error; err != nil {
		return fmt.Errorf("setup: create session: %w", err)
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("setup: commit: %w", err)
	}

	committed = true

	// Refresh the hasUsers cache now that the row is visible to the RO handle.
	s.refreshHasUsersCache()

	return nil
}

// ErrSetupAlreadyDone is returned by SetupFirstAdmin when any user row
// already exists at setup time.
var ErrSetupAlreadyDone = errors.New("setup has already been completed")

// ResetPassword updates a user's password hash and invalidates all their
// sessions. Every password-change path in the system MUST go through this
// (or equivalently: MUST call DeleteSessionsForUser) to honor the security
// invariant that credential changes drop existing sessions.
//
// If session invalidation fails, the error is returned so the caller does
// NOT mint a fresh session on top of a potentially-still-valid old one.
func (s *ConfigStore) ResetPassword(userID uint, newHash string) error {
	if err := s.db.Model(&User{}).Where("id = ?", userID).Update("password_hash", newHash).Error; err != nil {
		return fmt.Errorf("reset password: %w", err)
	}

	if err := s.DeleteSessionsForUser(userID); err != nil {
		return fmt.Errorf("reset password: %w", err)
	}

	return nil
}
