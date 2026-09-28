// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package configstore

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Auth storage", func() {
	var store *ConfigStore

	BeforeEach(func() {
		tmpDir := GinkgoT().TempDir()
		dbPath := filepath.Join(tmpDir, "auth.db")

		var err error
		store, err = Open(dbPath)
		Expect(err).Should(Succeed())
		DeferCleanup(store.Close)
	})

	Describe("HasUsers cold-path caching", func() {
		It("returns false on a fresh DB", func() {
			Expect(store.HasUsers()).Should(BeFalse())
		})

		It("re-queries the DB when another connection seeds a user while the cache is false", func() {
			// Freeze the last-check clock to "just now" so the next HasUsers()
			// call stays within the 5s soft TTL and does NOT hit the DB.
			store.hasUsersLastCheck.Store(time.Now().UnixNano())

			// Simulate a different-PID CLI writing a user by bypassing the
			// normal CreateUser path (which refreshes the in-process cache).
			Expect(store.db.Create(&User{
				Username:     "cliuser",
				PasswordHash: "x",
				Role:         "admin",
			}).Error).Should(Succeed())

			// Within the TTL: cache still false, DB not re-queried.
			Expect(store.HasUsers()).Should(BeFalse())

			// Rewind the last-check timestamp past the TTL to force the next
			// HasUsers() through the cold path without actually sleeping.
			store.hasUsersLastCheck.Store(
				time.Now().Add(-2 * hasUsersColdTTL).UnixNano(),
			)

			// Cold path re-queries, flips cache true.
			Expect(store.HasUsers()).Should(BeTrue())

			// Subsequent calls must short-circuit on the cached true
			// regardless of the TTL clock.
			Expect(store.HasUsers()).Should(BeTrue())
		})

		It("short-circuits on cached true without touching the DB clock", func() {
			Expect(store.CreateUser(&User{
				Username:     "seed",
				PasswordHash: "x",
				Role:         "admin",
			})).Should(Succeed())

			// CreateUser refreshes the cache; HasUsers must now return true
			// regardless of hasUsersLastCheck.
			before := store.hasUsersLastCheck.Load()
			Expect(store.HasUsers()).Should(BeTrue())
			Expect(store.hasUsersLastCheck.Load()).Should(Equal(before))
		})
	})

	Describe("username case-insensitive lookup", func() {
		It("finds a user regardless of caller casing", func() {
			Expect(store.CreateUser(&User{
				Username:     "Alice",
				PasswordHash: "x",
				Role:         "admin",
			})).Should(Succeed())

			u, err := store.GetUserByUsername("ALICE")
			Expect(err).Should(Succeed())
			Expect(u.Username).Should(Equal("alice"))

			u2, err := store.GetUserByUsername("alice")
			Expect(err).Should(Succeed())
			Expect(u2.ID).Should(Equal(u.ID))
		})
	})

	Describe("DeleteSessionsForUser", func() {
		It("removes all sessions for the user and publishes a revocation signal", func() {
			Expect(store.CreateUser(&User{
				Username:     "bob",
				PasswordHash: "x",
				Role:         "viewer",
			})).Should(Succeed())

			u, err := store.GetUserByUsername("bob")
			Expect(err).Should(Succeed())

			s1, err := store.CreateSession(u.ID)
			Expect(err).Should(Succeed())
			s2, err := store.CreateSession(u.ID)
			Expect(err).Should(Succeed())

			// Pre-check: both sessions are retrievable.
			_, err = store.GetSession(s1.ID)
			Expect(err).Should(Succeed())
			_, err = store.GetSession(s2.ID)
			Expect(err).Should(Succeed())

			Expect(store.DeleteSessionsForUser(u.ID)).Should(Succeed())

			// Revocation signal fires with the userID.
			select {
			case uid := <-store.SessionRevoked():
				Expect(uid).Should(Equal(u.ID))
			case <-time.After(100 * time.Millisecond):
				Fail("expected SessionRevoked signal, got none")
			}

			// All sessions are gone.
			_, err = store.GetSession(s1.ID)
			Expect(err).Should(HaveOccurred())
			_, err = store.GetSession(s2.ID)
			Expect(err).Should(HaveOccurred())
		})

		It("does not block when the revocation channel buffer is saturated", func() {
			Expect(store.CreateUser(&User{
				Username:     "carol",
				PasswordHash: "x",
				Role:         "viewer",
			})).Should(Succeed())

			u, err := store.GetUserByUsername("carol")
			Expect(err).Should(Succeed())

			// Fill the buffer (16) plus some extra — extras must drop, not block.
			done := make(chan struct{})
			go func() {
				defer close(done)
				for range 64 {
					_ = store.DeleteSessionsForUser(u.ID)
				}
			}()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				Fail("DeleteSessionsForUser blocked on a full revocation channel")
			}
		})
	})

	Describe("DeleteUser last-admin invariant", func() {
		It("refuses to delete the sole admin", func() {
			Expect(store.CreateUser(&User{
				Username:     "only-admin",
				PasswordHash: "x",
				Role:         "admin",
			})).Should(Succeed())

			u, err := store.GetUserByUsername("only-admin")
			Expect(err).Should(Succeed())

			err = store.DeleteUser(u.ID)
			Expect(err).Should(MatchError(ErrLastAdmin))

			// User still present.
			_, err = store.GetUser(u.ID)
			Expect(err).Should(Succeed())
		})

		It("allows deleting an admin when another admin remains", func() {
			Expect(store.CreateUser(&User{
				Username:     "admin-a",
				PasswordHash: "x",
				Role:         "admin",
			})).Should(Succeed())
			Expect(store.CreateUser(&User{
				Username:     "admin-b",
				PasswordHash: "x",
				Role:         "admin",
			})).Should(Succeed())

			a, err := store.GetUserByUsername("admin-a")
			Expect(err).Should(Succeed())

			Expect(store.DeleteUser(a.ID)).Should(Succeed())

			_, err = store.GetUser(a.ID)
			Expect(err).Should(HaveOccurred())
		})

		It("allows deleting a viewer even when only one admin exists", func() {
			Expect(store.CreateUser(&User{
				Username:     "sole-admin",
				PasswordHash: "x",
				Role:         "admin",
			})).Should(Succeed())
			Expect(store.CreateUser(&User{
				Username:     "viewer",
				PasswordHash: "x",
				Role:         "viewer",
			})).Should(Succeed())

			v, err := store.GetUserByUsername("viewer")
			Expect(err).Should(Succeed())
			Expect(store.DeleteUser(v.ID)).Should(Succeed())
		})

		// Two concurrent goroutines try to delete two distinct admins while a
		// third user (viewer) exists. The BEGIN IMMEDIATE transaction
		// serializes them: the first commits and drops admin_count to 1; the
		// second then reads admin_count=1 inside its own tx and must return
		// ErrLastAdmin. Final state: exactly one admin row remains.
		It("serializes concurrent deletions so at least one admin always remains", func() {
			Expect(store.CreateUser(&User{
				Username:     "admin-x",
				PasswordHash: "x",
				Role:         "admin",
			})).Should(Succeed())
			Expect(store.CreateUser(&User{
				Username:     "admin-y",
				PasswordHash: "x",
				Role:         "admin",
			})).Should(Succeed())
			Expect(store.CreateUser(&User{
				Username:     "viewer-z",
				PasswordHash: "x",
				Role:         "viewer",
			})).Should(Succeed())

			x, err := store.GetUserByUsername("admin-x")
			Expect(err).Should(Succeed())
			y, err := store.GetUserByUsername("admin-y")
			Expect(err).Should(Succeed())

			var (
				wg       sync.WaitGroup
				successN atomic.Int32
				lastN    atomic.Int32
				start    = make(chan struct{})
			)

			wg.Add(2)

			for _, id := range []uint{x.ID, y.ID} {
				go func() {
					defer wg.Done()
					<-start

					err := store.DeleteUser(id)
					switch {
					case err == nil:
						successN.Add(1)
					case errors.Is(err, ErrLastAdmin):
						lastN.Add(1)
					default:
						GinkgoT().Errorf("unexpected DeleteUser error: %v", err)
					}
				}()
			}

			close(start)
			wg.Wait()

			// Exactly one delete succeeds; the other is blocked by the
			// last-admin invariant.
			Expect(successN.Load()).Should(BeEquivalentTo(1))
			Expect(lastN.Load()).Should(BeEquivalentTo(1))

			// Verify exactly one admin remains.
			users, err := store.ListUsers()
			Expect(err).Should(Succeed())

			adminCount := 0

			for _, u := range users {
				if u.Role == "admin" {
					adminCount++
				}
			}

			Expect(adminCount).Should(Equal(1))
		})
	})

	Describe("ExtendSession idempotency", func() {
		It("advances the expiry forward but never backward", func() {
			Expect(store.CreateUser(&User{
				Username:     "dave",
				PasswordHash: "x",
				Role:         "viewer",
			})).Should(Succeed())

			u, err := store.GetUserByUsername("dave")
			Expect(err).Should(Succeed())

			sess, err := store.CreateSession(u.ID)
			Expect(err).Should(Succeed())

			// Push forward.
			forward := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
			Expect(store.ExtendSession(sess.ID, forward)).Should(Succeed())

			got, err := store.GetSession(sess.ID)
			Expect(err).Should(Succeed())
			Expect(got.ExpiresAt.UTC().Truncate(time.Second)).Should(Equal(forward))

			// Attempting to push backward must be a no-op (idempotent guard).
			backward := time.Now().Add(1 * time.Hour).UTC().Truncate(time.Second)
			Expect(store.ExtendSession(sess.ID, backward)).Should(Succeed())

			got2, err := store.GetSession(sess.ID)
			Expect(err).Should(Succeed())
			Expect(got2.ExpiresAt.UTC().Truncate(time.Second)).Should(Equal(forward))
		})

		It("is a no-op when the session does not exist", func() {
			Expect(
				store.ExtendSession("does-not-exist", time.Now().Add(time.Hour)),
			).Should(Succeed())
		})
	})

	Describe("PruneExpiredSessions", func() {
		It("removes only sessions with expires_at in the past", func() {
			Expect(store.CreateUser(&User{
				Username:     "eve",
				PasswordHash: "x",
				Role:         "viewer",
			})).Should(Succeed())

			u, err := store.GetUserByUsername("eve")
			Expect(err).Should(Succeed())

			// One expired, one future. Write ExpiresAt directly to bypass
			// the 24h default in CreateSession.
			expired := &Session{
				ID:        "expired-token",
				UserID:    u.ID,
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			}
			fresh := &Session{
				ID:        "fresh-token",
				UserID:    u.ID,
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}
			Expect(store.db.Create(expired).Error).Should(Succeed())
			Expect(store.db.Create(fresh).Error).Should(Succeed())

			Expect(store.PruneExpiredSessions()).Should(Succeed())

			var count int64
			store.roDB.Model(&Session{}).Where("id = ?", "expired-token").Count(&count)
			Expect(count).Should(BeNumerically("==", 0))

			store.roDB.Model(&Session{}).Where("id = ?", "fresh-token").Count(&count)
			Expect(count).Should(BeNumerically("==", 1))
		})
	})

	Describe("ResetPassword", func() {
		It("updates the hash and invalidates existing sessions", func() {
			Expect(store.CreateUser(&User{
				Username:     "frank",
				PasswordHash: "old-hash",
				Role:         "admin",
			})).Should(Succeed())

			u, err := store.GetUserByUsername("frank")
			Expect(err).Should(Succeed())

			sess, err := store.CreateSession(u.ID)
			Expect(err).Should(Succeed())

			// Drain any prior revocation signals so the assertion below is
			// unambiguous.
			drainRevocations(store)

			Expect(store.ResetPassword(u.ID, "new-hash")).Should(Succeed())

			select {
			case uid := <-store.SessionRevoked():
				Expect(uid).Should(Equal(u.ID))
			case <-time.After(100 * time.Millisecond):
				Fail("expected SessionRevoked signal from ResetPassword")
			}

			_, err = store.GetSession(sess.ID)
			Expect(err).Should(HaveOccurred())

			updated, err := store.GetUser(u.ID)
			Expect(err).Should(Succeed())
			Expect(updated.PasswordHash).Should(Equal("new-hash"))
		})
	})

	Describe("CreateSession token format", func() {
		It("issues 64-hex-char tokens (32 bytes of randomness)", func() {
			Expect(store.CreateUser(&User{
				Username:     "gina",
				PasswordHash: "x",
				Role:         "viewer",
			})).Should(Succeed())

			u, err := store.GetUserByUsername("gina")
			Expect(err).Should(Succeed())

			seen := map[string]bool{}
			for range 8 {
				sess, err := store.CreateSession(u.ID)
				Expect(err).Should(Succeed())
				Expect(sess.ID).Should(HaveLen(64))
				Expect(seen[sess.ID]).Should(BeFalse(), "tokens must be unique")
				seen[sess.ID] = true
			}
		})
	})
})

// drainRevocations empties the session-revocation channel without blocking.
// Tests that need a clean channel before asserting on a fresh signal use it.
func drainRevocations(s *ConfigStore) {
	for {
		select {
		case <-s.SessionRevoked():
		default:
			return
		}
	}
}
