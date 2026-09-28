// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestConstants(t *testing.T) {
	t.Parallel()

	if MinPasswordLength != 12 {
		t.Errorf("MinPasswordLength = %d, want 12", MinPasswordLength)
	}

	if SessionDuration != 24*time.Hour {
		t.Errorf("SessionDuration = %v, want 24h", SessionDuration)
	}

	if SessionSlidingThreshold != 12*time.Hour {
		t.Errorf("SessionSlidingThreshold = %v, want 12h", SessionSlidingThreshold)
	}

	if SessionCookieName != "blockasaurus_session" {
		t.Errorf("SessionCookieName = %q, want blockasaurus_session", SessionCookieName)
	}

	if SessionCookieNameSecure != "__Host-blockasaurus_session" {
		t.Errorf("SessionCookieNameSecure = %q, want __Host-blockasaurus_session", SessionCookieNameSecure)
	}

	if SessionTokenBytes != 32 {
		t.Errorf("SessionTokenBytes = %d, want 32", SessionTokenBytes)
	}

	if RoleAdmin != "admin" {
		t.Errorf("RoleAdmin = %q, want admin", RoleAdmin)
	}

	if RoleViewer != "viewer" {
		t.Errorf("RoleViewer = %q, want viewer", RoleViewer)
	}
}

func TestHashPassword_Succeeds(t *testing.T) {
	t.Parallel()

	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if hash == "" {
		t.Fatal("HashPassword returned empty hash")
	}

	// Verify the result is actually a valid bcrypt hash at DefaultCost.
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("result is not a valid bcrypt hash: %v", err)
	}

	if cost != bcrypt.DefaultCost {
		t.Errorf("bcrypt cost = %d, want DefaultCost (%d)", cost, bcrypt.DefaultCost)
	}
}

func TestHashPassword_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := HashPassword("")
	if !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("HashPassword(\"\") error = %v, want ErrEmptyPassword", err)
	}
}

func TestHashPassword_ProducesUniqueHashes(t *testing.T) {
	t.Parallel()

	// bcrypt salts each hash, so identical inputs must produce different outputs.
	pw := "correct horse battery staple"

	h1, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("first hash failed: %v", err)
	}

	h2, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("second hash failed: %v", err)
	}

	if h1 == h2 {
		t.Error("two hashes of the same password collided; bcrypt salting is broken")
	}
}

func TestCheckPassword_Matches(t *testing.T) {
	t.Parallel()

	pw := "correct horse battery staple"

	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !CheckPassword(hash, pw) {
		t.Error("CheckPassword returned false for matching password")
	}
}

func TestCheckPassword_Mismatch(t *testing.T) {
	t.Parallel()

	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if CheckPassword(hash, "wrong password here") {
		t.Error("CheckPassword returned true for non-matching password")
	}
}

func TestCheckPassword_MalformedHash(t *testing.T) {
	t.Parallel()

	// A garbage string is not a valid bcrypt hash — CheckPassword must
	// return false (never panic, never return an error).
	if CheckPassword("not-a-bcrypt-hash", "anything") {
		t.Error("CheckPassword returned true for malformed hash")
	}
}

func TestValidatePassword_Accepts(t *testing.T) {
	t.Parallel()

	// Exactly MinPasswordLength characters is acceptable.
	if err := ValidatePassword(strings.Repeat("a", MinPasswordLength)); err != nil {
		t.Errorf("ValidatePassword rejected a %d-char password: %v", MinPasswordLength, err)
	}

	if err := ValidatePassword("correct horse battery staple"); err != nil {
		t.Errorf("ValidatePassword rejected a long password: %v", err)
	}
}

func TestValidatePassword_RejectsShort(t *testing.T) {
	t.Parallel()

	err := ValidatePassword(strings.Repeat("a", MinPasswordLength-1))
	if err == nil {
		t.Fatal("ValidatePassword accepted a too-short password")
	}

	if !strings.Contains(err.Error(), "12") {
		t.Errorf("error message %q does not mention the minimum length", err.Error())
	}
}

func TestValidatePassword_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if err := ValidatePassword(""); err == nil {
		t.Error("ValidatePassword accepted an empty password")
	}
}

func TestGenerateSessionToken_Format(t *testing.T) {
	t.Parallel()

	tok, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken returned error: %v", err)
	}

	wantLen := SessionTokenBytes * 2
	if len(tok) != wantLen {
		t.Errorf("token length = %d, want %d", len(tok), wantLen)
	}

	// Must be valid hex that decodes to exactly SessionTokenBytes.
	raw, err := hex.DecodeString(tok)
	if err != nil {
		t.Fatalf("token is not valid hex: %v", err)
	}

	if len(raw) != SessionTokenBytes {
		t.Errorf("decoded token = %d bytes, want %d", len(raw), SessionTokenBytes)
	}
}

func TestGenerateSessionToken_Unique(t *testing.T) {
	t.Parallel()

	// Collision across a small set would indicate a crypto/rand failure
	// or accidental determinism.
	const iterations = 100

	seen := make(map[string]struct{}, iterations)

	for i := range iterations {
		tok, err := GenerateSessionToken()
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}

		if _, dup := seen[tok]; dup {
			t.Fatalf("duplicate token at iter %d: %s", i, tok)
		}

		seen[tok] = struct{}{}
	}
}

func TestValidateRole_Accepts(t *testing.T) {
	t.Parallel()

	for _, role := range []string{RoleAdmin, RoleViewer} {
		if err := ValidateRole(role); err != nil {
			t.Errorf("ValidateRole(%q) = %v, want nil", role, err)
		}
	}
}

func TestValidateRole_Rejects(t *testing.T) {
	t.Parallel()

	for _, role := range []string{
		"",
		"ADMIN",   // case-sensitive
		"Admin",   // case-sensitive
		"viewer ", // trailing whitespace rejected
		"root",
		"superuser",
	} {
		if err := ValidateRole(role); err == nil {
			t.Errorf("ValidateRole(%q) returned nil, want error", role)
		}
	}
}

func TestValidateUsername_Accepts(t *testing.T) {
	t.Parallel()

	for _, u := range []string{
		"abc",                                  // minimum length
		"alice",                                // common
		"admin",                                // common
		"a.b",                                  // dot allowed
		"a-b",                                  // hyphen allowed
		"a_b",                                  // underscore allowed
		"user.name_01",                         // combination
		strings.Repeat("a", UsernameMaxLength), // maximum length
	} {
		if err := ValidateUsername(u); err != nil {
			t.Errorf("ValidateUsername(%q) = %v, want nil", u, err)
		}
	}
}

func TestValidateUsername_RejectsTooShort(t *testing.T) {
	t.Parallel()

	for _, u := range []string{"", "a", "ab"} {
		if err := ValidateUsername(u); err == nil {
			t.Errorf("ValidateUsername(%q) returned nil, want error", u)
		}
	}
}

func TestValidateUsername_RejectsTooLong(t *testing.T) {
	t.Parallel()

	u := strings.Repeat("a", UsernameMaxLength+1)
	if err := ValidateUsername(u); err == nil {
		t.Errorf("ValidateUsername(%d chars) returned nil, want error", len(u))
	}
}

func TestValidateUsername_RejectsUppercase(t *testing.T) {
	t.Parallel()

	// Callers must lowercase before calling ValidateUsername; uppercase is
	// treated as an invalid-charset error rather than silently accepted.
	for _, u := range []string{"Alice", "ADMIN", "aBc"} {
		if err := ValidateUsername(u); err == nil {
			t.Errorf("ValidateUsername(%q) returned nil, want error (uppercase)", u)
		}
	}
}

func TestValidateUsername_RejectsInvalidCharset(t *testing.T) {
	t.Parallel()

	for _, u := range []string{
		"alice!",
		"al ice",
		"a@b",
		"a/b",
		"a\\b",
		"a:b",
		"a+b",
		"a#b",
		"a\tb",
	} {
		if err := ValidateUsername(u); err == nil {
			t.Errorf("ValidateUsername(%q) returned nil, want error (invalid char)", u)
		}
	}
}
