// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

// Package authmodels holds the User and Session GORM models. It is a leaf
// package so both the auth primitives (github.com/0xERR0R/blocky/auth) and
// the configstore (github.com/0xERR0R/blocky/configstore) can import it
// without forming an import cycle. configstore re-exports the types as
// aliases (configstore.User, configstore.Session) so existing call sites
// keep compiling.
package authmodels

import "time"

// User is the persisted account row.
type User struct {
	ID           uint      `gorm:"primaryKey"                json:"id"`
	Username     string    `gorm:"uniqueIndex;not null"      json:"username"`
	PasswordHash string    `gorm:"not null"                  json:"-"`
	Role         string    `gorm:"not null;default:'viewer'" json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Session is the persisted session row keyed by an opaque token.
type Session struct {
	ID        string    `gorm:"primaryKey;size:64" json:"id"`
	UserID    uint      `gorm:"index;not null"     json:"user_id"`
	ExpiresAt time.Time `gorm:"index;not null"     json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
