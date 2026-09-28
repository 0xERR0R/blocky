// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package configstore

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/0xERR0R/blocky/auth/authmodels"
)

type ClientGroup struct {
	ID        uint       `gorm:"primaryKey"                      json:"id"`
	Name      string     `gorm:"uniqueIndex;not null"            json:"name"`
	Slug      string     `gorm:"uniqueIndex;not null;default:''" json:"slug"`
	Clients   StringList `gorm:"type:text;not null;default:'[]'" json:"clients"`
	Groups    StringList `gorm:"type:text;not null;default:'[]'" json:"groups"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type BlocklistSource struct {
	ID         uint      `gorm:"primaryKey"            json:"id"`
	GroupName  string    `gorm:"index;not null"        json:"group_name"`
	ListType   string    `gorm:"not null"              json:"list_type"`
	SourceType string    `gorm:"not null"              json:"source_type"`
	Source     string    `gorm:"not null"              json:"source"`
	Enabled    *bool     `gorm:"not null;default:true" json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type CustomDNSEntry struct {
	ID         uint      `gorm:"primaryKey"                          json:"id"`
	Domain     string    `gorm:"uniqueIndex:idx_dns_unique;not null" json:"domain"`
	RecordType string    `gorm:"uniqueIndex:idx_dns_unique;not null" json:"record_type"`
	Value      string    `gorm:"uniqueIndex:idx_dns_unique;not null" json:"value"`
	TTL        uint32    `gorm:"not null;default:3600"               json:"ttl"`
	Enabled    *bool     `gorm:"not null;default:true"               json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// UpstreamGroup is a named collection of upstream DNS servers.
type UpstreamGroup struct {
	ID        uint      `gorm:"primaryKey"                      json:"id"`
	Name      string    `gorm:"uniqueIndex;not null"            json:"name"`
	Slug      string    `gorm:"uniqueIndex;not null;default:''" json:"slug"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpstreamServer is an individual upstream DNS server URL, belonging to an UpstreamGroup.
// URL is the same string format consumed by config.ParseUpstream (e.g. "1.1.1.1",
// "tcp-tls:dns.example.com", "https://dns.google/dns-query", "sdns://...").
type UpstreamServer struct {
	ID        uint      `gorm:"primaryKey"            json:"id"`
	GroupName string    `gorm:"index;not null"        json:"group_name"`
	URL       string    `gorm:"not null"              json:"url"`
	Position  int       `gorm:"not null;default:0"    json:"position"`
	Enabled   *bool     `gorm:"not null;default:true" json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpstreamSettings holds global upstream configuration (singleton).
type UpstreamSettings struct {
	ID           uint      `gorm:"primaryKey"                       json:"id"`
	Strategy     string    `gorm:"not null;default:'parallel_best'" json:"strategy"`
	Timeout      string    `gorm:"not null;default:'2s'"            json:"timeout"`
	UserAgent    string    `gorm:"not null;default:''"              json:"user_agent"`
	InitStrategy string    `gorm:"not null;default:'blocking'"      json:"init_strategy"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// IsEnabled returns the Enabled value, defaulting to true if nil.
func (u *UpstreamServer) IsEnabled() bool { return u.Enabled == nil || *u.Enabled }

type BlockSettings struct {
	ID        uint      `gorm:"primaryKey"                json:"id"`
	BlockType string    `gorm:"not null;default:'ZEROIP'" json:"block_type"`
	BlockTTL  string    `gorm:"not null;default:'6h'"     json:"block_ttl"`
	UpdatedAt time.Time `json:"updated_at"`
}

// StringList is a []string that serializes to/from JSON text in SQLite.
type StringList []string

func (s StringList) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}

	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal StringList: %w", err)
	}

	return string(b), nil
}

func (s *StringList) Scan(value any) error {
	if value == nil {
		*s = StringList{}

		return nil
	}

	var bytes []byte

	switch v := value.(type) {
	case string:
		bytes = []byte(v)
	case []byte:
		bytes = v
	default:
		return fmt.Errorf("unsupported StringList scan type: %T", value)
	}

	return json.Unmarshal(bytes, s)
}

func (StringList) GormDataType() string {
	return "text"
}

// DomainEntry is an individual domain block/allow rule (exact or regex).
// GroupName is a hidden blocking group identifier (like BlocklistSource.GroupName)
// used to wire the entry into client groups via their Groups array.
type DomainEntry struct {
	ID        uint      `gorm:"primaryKey"            json:"id"`
	Domain    string    `gorm:"not null"              json:"domain"`
	EntryType string    `gorm:"not null;index"        json:"entry_type"` // exact_deny, regex_deny, exact_allow, regex_allow
	Comment   string    `json:"comment"`
	Enabled   *bool     `gorm:"not null;default:true" json:"enabled"`
	GroupName string    `gorm:"not null;default:''"   json:"group_name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsEnabled returns the Enabled value, defaulting to true if nil.
func (s *BlocklistSource) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// IsEnabled returns the Enabled value, defaulting to true if nil.
func (e *CustomDNSEntry) IsEnabled() bool { return e.Enabled == nil || *e.Enabled }

// IsEnabled returns the Enabled value, defaulting to true if nil.
func (d *DomainEntry) IsEnabled() bool { return d.Enabled == nil || *d.Enabled }

// --- Auth models ---
//
// The User and Session structs live in auth/authmodels so that both the
// auth package (for middleware types) and configstore (for AutoMigrate and
// CRUD) can reference them without forming an import cycle. Re-exported
// here as type aliases to preserve existing call sites (configstore.User,
// configstore.Session).

type (
	User    = authmodels.User
	Session = authmodels.Session
)

// --- Stats persistence models ---

// StatsBucket stores a single 10-minute aggregation window.
type StatsBucket struct {
	Timestamp     int64  `gorm:"primaryKey"` // Unix seconds, truncated to 10min
	Total         int    `gorm:"not null;default:0"`
	Blocked       int    `gorm:"not null;default:0"`
	ClientCounts  string `gorm:"type:text;not null;default:'{}'"` // JSON map[string]int
	LatencySum    int64  `gorm:"not null;default:0"`              // sum of upstream latencies, nanoseconds
	UpstreamCount int    `gorm:"not null;default:0"`              // number of upstream-resolved queries
}

func (StatsBucket) TableName() string { return "stats_buckets" }

// StatsCounter stores a running counter for a given category and key.
type StatsCounter struct {
	Category string `gorm:"primaryKey;not null"` // domain_permitted, domain_blocked, client_total, client_blocked, query_type, response_type
	Key      string `gorm:"primaryKey;not null"`
	Count    int    `gorm:"not null;default:0"`
}

func (StatsCounter) TableName() string { return "stats_counters" }
