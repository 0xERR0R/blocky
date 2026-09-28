// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package configstore

import (
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/util"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type ConfigStore struct {
	db                *gorm.DB // read-write, MaxOpenConns=1 (preserved for write serialization)
	roDB              *gorm.DB // read-only for auth lookups, MaxOpenConns=4
	hasUsersCache     atomic.Bool
	hasUsersLastCheck atomic.Int64 // unix-nano of last cold-path re-query

	// sessionRevoked fans out userID revocation signals to in-process consumers
	// (e.g., the WebSocket log broadcaster) so active sockets can be closed when
	// a user is deleted or all their sessions are invalidated. Buffered so that
	// auth write paths (DeleteSessionsForUser) never block on a slow consumer.
	sessionRevoked chan uint
}

func Open(path string) (*ConfigStore, error) {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("open config database: %w", err)
	}

	// SQLite: single writer, avoid connection pool contention
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get underlying sql.DB: %w", err)
	}

	sqlDB.SetMaxOpenConns(1)

	// Enable WAL mode for concurrent reads during DNS resolution
	if err := db.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		return nil, fmt.Errorf("enable WAL mode: %w", err)
	}

	if err := db.Exec("PRAGMA busy_timeout=5000").Error; err != nil {
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}

	// Read-only connection for auth lookups (session checks on every request).
	//
	// The glebarez/go-sqlite driver strips query parameters from the DSN before
	// passing it to sqlite3 unless the DSN is prefixed with "file:" — only then
	// does SQLITE_OPEN_URI kick in and SQLite's own URI parser honor mode=ro.
	// So we build a proper file: URI here. As belt-and-suspenders we also apply
	// PRAGMA query_only=1 on the handle after open, which enforces read-only
	// at the SQLite statement layer even if the URI parsing ever regresses.
	roDSN := "file:" + path + "?mode=ro"

	roDB, err := gorm.Open(sqlite.Open(roDSN), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("open read-only config database: %w", err)
	}

	roSQL, err := roDB.DB()
	if err != nil {
		return nil, fmt.Errorf("get underlying read-only sql.DB: %w", err)
	}

	roSQL.SetMaxOpenConns(4)

	if err := roDB.Exec("PRAGMA busy_timeout=5000").Error; err != nil {
		return nil, fmt.Errorf("set read-only busy timeout: %w", err)
	}

	// WAL mode is set by the RW handle; the roDB picks it up from the shared
	// journal_mode on the database file. Still, explicitly ensure any
	// subsequent connections in this pool see the same pragmas.
	if err := roDB.Exec("PRAGMA query_only=1").Error; err != nil {
		return nil, fmt.Errorf("set read-only query_only: %w", err)
	}

	if err := db.AutoMigrate(
		&ClientGroup{},
		&BlocklistSource{},
		&CustomDNSEntry{},
		&DomainEntry{},
		&BlockSettings{},
		&UpstreamGroup{},
		&UpstreamServer{},
		&UpstreamSettings{},
		&StatsBucket{},
		&StatsCounter{},
		&User{},
		&Session{},
	); err != nil {
		return nil, fmt.Errorf("auto-migrate config tables: %w", err)
	}

	// Backfill group_name for domain entries migrated from the old Groups column
	if err := db.Exec(
		`UPDATE domain_entries SET group_name = '_d_' || id WHERE group_name = '' OR group_name IS NULL`,
	).Error; err != nil {
		return nil, fmt.Errorf("backfill domain entry group names: %w", err)
	}

	store := &ConfigStore{
		db:             db,
		roDB:           roDB,
		sessionRevoked: make(chan uint, 16),
	}

	// Seed hasUsers cache from the DB once at open.
	store.refreshHasUsersCache()

	// Backfill slugs for client groups that predate the slug column
	if err := store.backfillClientGroupSlugs(); err != nil {
		return nil, fmt.Errorf("backfill client group slugs: %w", err)
	}

	if err := store.ensureDomainEntriesInDefaultGroup(); err != nil {
		return nil, fmt.Errorf("wire domain entries to default group: %w", err)
	}

	if err := store.seedDefaultUpstreams(); err != nil {
		return nil, fmt.Errorf("seed default upstreams: %w", err)
	}

	return store, nil
}

func (s *ConfigStore) Close() error {
	if s.roDB != nil {
		if roDB, err := s.roDB.DB(); err == nil {
			roDB.Close()
		}
	}

	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}

	return sqlDB.Close()
}

// --- ClientGroup CRUD ---

func (s *ConfigStore) ListClientGroups() ([]ClientGroup, error) {
	var groups []ClientGroup
	if err := s.db.Order("name").Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("list client groups: %w", err)
	}

	return groups, nil
}

func (s *ConfigStore) GetClientGroup(name string) (*ClientGroup, error) {
	var g ClientGroup
	if err := s.db.Where("name = ?", name).First(&g).Error; err != nil {
		return nil, fmt.Errorf("get client group %q: %w", name, err)
	}

	return &g, nil
}

func (s *ConfigStore) GetClientGroupBySlug(slug string) (*ClientGroup, error) {
	var g ClientGroup
	if err := s.db.Where("slug = ?", slug).First(&g).Error; err != nil {
		return nil, fmt.Errorf("get client group by slug %q: %w", slug, err)
	}

	return &g, nil
}

// PutClientGroup upserts a client group by name.
// The Slug field is always regenerated from the Name.
func (s *ConfigStore) PutClientGroup(g *ClientGroup) error {
	g.Slug = util.SanitizeGroupSlug(g.Name)
	if g.Slug == "" {
		return fmt.Errorf("client group name %q produces an empty slug", g.Name)
	}

	// Check for slug collision with a different group
	var collision ClientGroup
	if err := s.db.Where("slug = ? AND name != ?", g.Slug, g.Name).First(&collision).Error; err == nil {
		return fmt.Errorf("slug %q already used by client group %q", g.Slug, collision.Name)
	}

	var existing ClientGroup

	err := s.db.Where("name = ?", g.Name).First(&existing).Error
	if err == nil {
		g.ID = existing.ID
		g.CreatedAt = existing.CreatedAt

		if err := s.db.Save(g).Error; err != nil {
			return fmt.Errorf("update client group %q: %w", g.Name, err)
		}

		return nil
	}

	if err := s.db.Create(g).Error; err != nil {
		return fmt.Errorf("create client group %q: %w", g.Name, err)
	}

	return nil
}

func (s *ConfigStore) DeleteClientGroup(name string) error {
	result := s.db.Where("name = ?", name).Delete(&ClientGroup{})
	if result.Error != nil {
		return fmt.Errorf("delete client group %q: %w", name, result.Error)
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

// AddGroupToClientGroup appends groupName to a client group's Groups list if not already present.
func (s *ConfigStore) AddGroupToClientGroup(clientGroupName, groupName string) error {
	g, err := s.GetClientGroup(clientGroupName)
	if err != nil {
		return err
	}

	if slices.Contains(g.Groups, groupName) {
		return nil
	}

	g.Groups = append(g.Groups, groupName)

	return s.PutClientGroup(g)
}

// RemoveGroupFromAllClientGroups removes groupName from every client group's Groups list.
func (s *ConfigStore) RemoveGroupFromAllClientGroups(groupName string) error {
	groups, err := s.ListClientGroups()
	if err != nil {
		return err
	}

	for i := range groups {
		g := &groups[i]
		filtered := make(StringList, 0, len(g.Groups))

		for _, name := range g.Groups {
			if name != groupName {
				filtered = append(filtered, name)
			}
		}

		if len(filtered) != len(g.Groups) {
			g.Groups = filtered
			if err := s.PutClientGroup(g); err != nil {
				return err
			}
		}
	}

	return nil
}

// ensureDomainEntriesInDefaultGroup adds any domain entry group_names
// missing from the default client group. Runs on startup to handle
// entries migrated from the old Groups-based model.
func (s *ConfigStore) ensureDomainEntriesInDefaultGroup() error {
	entries, err := s.ListDomainEntries("")
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		return nil
	}

	defGroup, err := s.GetClientGroup("default")
	if err != nil {
		return nil // no default group — nothing to wire
	}

	existing := make(map[string]bool, len(defGroup.Groups))
	for _, g := range defGroup.Groups {
		existing[g] = true
	}

	changed := false

	for _, e := range entries {
		if e.GroupName != "" && !existing[e.GroupName] {
			defGroup.Groups = append(defGroup.Groups, e.GroupName)
			existing[e.GroupName] = true
			changed = true
		}
	}

	if changed {
		return s.PutClientGroup(defGroup)
	}

	return nil
}

// backfillClientGroupSlugs populates empty slugs for groups created before
// the slug column was added.
func (s *ConfigStore) backfillClientGroupSlugs() error {
	var groups []ClientGroup
	if err := s.db.Where("slug = '' OR slug IS NULL").Find(&groups).Error; err != nil {
		return err
	}

	for i := range groups {
		groups[i].Slug = util.SanitizeGroupSlug(groups[i].Name)
		if groups[i].Slug == "" {
			groups[i].Slug = fmt.Sprintf("group-%d", groups[i].ID)
		}

		if err := s.db.Save(&groups[i]).Error; err != nil {
			return fmt.Errorf("backfill slug for group %q: %w", groups[i].Name, err)
		}
	}

	return nil
}

// --- BlocklistSource CRUD ---

func (s *ConfigStore) ListBlocklistSources(groupName, listType string) ([]BlocklistSource, error) {
	q := s.db.Order("id")

	if groupName != "" {
		q = q.Where("group_name = ?", groupName)
	}

	if listType != "" {
		q = q.Where("list_type = ?", listType)
	}

	var sources []BlocklistSource
	if err := q.Find(&sources).Error; err != nil {
		return nil, fmt.Errorf("list blocklist sources: %w", err)
	}

	return sources, nil
}

func (s *ConfigStore) GetBlocklistSource(id uint) (*BlocklistSource, error) {
	var src BlocklistSource
	if err := s.db.First(&src, id).Error; err != nil {
		return nil, fmt.Errorf("get blocklist source %d: %w", id, err)
	}

	return &src, nil
}

func (s *ConfigStore) CreateBlocklistSource(src *BlocklistSource) error {
	if err := s.db.Create(src).Error; err != nil {
		return fmt.Errorf("create blocklist source: %w", err)
	}

	return nil
}

func (s *ConfigStore) UpdateBlocklistSource(src *BlocklistSource) error {
	result := s.db.Save(src)
	if result.Error != nil {
		return fmt.Errorf("update blocklist source %d: %w", src.ID, result.Error)
	}

	return nil
}

func (s *ConfigStore) DeleteBlocklistSource(id uint) error {
	result := s.db.Delete(&BlocklistSource{}, id)
	if result.Error != nil {
		return fmt.Errorf("delete blocklist source %d: %w", id, result.Error)
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

// --- CustomDNSEntry CRUD ---

func (s *ConfigStore) ListCustomDNSEntries() ([]CustomDNSEntry, error) {
	var entries []CustomDNSEntry
	if err := s.db.Order("domain, record_type").Find(&entries).Error; err != nil {
		return nil, fmt.Errorf("list custom DNS entries: %w", err)
	}

	return entries, nil
}

func (s *ConfigStore) GetCustomDNSEntry(id uint) (*CustomDNSEntry, error) {
	var e CustomDNSEntry
	if err := s.db.First(&e, id).Error; err != nil {
		return nil, fmt.Errorf("get custom DNS entry %d: %w", id, err)
	}

	return &e, nil
}

func (s *ConfigStore) CreateCustomDNSEntry(e *CustomDNSEntry) error {
	if err := s.db.Create(e).Error; err != nil {
		return fmt.Errorf("create custom DNS entry: %w", err)
	}

	return nil
}

func (s *ConfigStore) UpdateCustomDNSEntry(e *CustomDNSEntry) error {
	result := s.db.Save(e)
	if result.Error != nil {
		return fmt.Errorf("update custom DNS entry %d: %w", e.ID, result.Error)
	}

	return nil
}

func (s *ConfigStore) DeleteCustomDNSEntry(id uint) error {
	result := s.db.Delete(&CustomDNSEntry{}, id)
	if result.Error != nil {
		return fmt.Errorf("delete custom DNS entry %d: %w", id, result.Error)
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

// --- DomainEntry CRUD ---

func (s *ConfigStore) ListDomainEntries(entryType string) ([]DomainEntry, error) {
	q := s.db.Order("domain")

	if entryType != "" {
		q = q.Where("entry_type = ?", entryType)
	}

	var entries []DomainEntry
	if err := q.Find(&entries).Error; err != nil {
		return nil, fmt.Errorf("list domain entries: %w", err)
	}

	return entries, nil
}

func (s *ConfigStore) GetDomainEntry(id uint) (*DomainEntry, error) {
	var e DomainEntry
	if err := s.db.First(&e, id).Error; err != nil {
		return nil, fmt.Errorf("get domain entry %d: %w", id, err)
	}

	return &e, nil
}

func (s *ConfigStore) CreateDomainEntry(e *DomainEntry) error {
	if err := s.db.Create(e).Error; err != nil {
		return fmt.Errorf("create domain entry: %w", err)
	}

	return nil
}

func (s *ConfigStore) UpdateDomainEntry(e *DomainEntry) error {
	result := s.db.Save(e)
	if result.Error != nil {
		return fmt.Errorf("update domain entry %d: %w", e.ID, result.Error)
	}

	return nil
}

func (s *ConfigStore) DeleteDomainEntry(id uint) error {
	result := s.db.Delete(&DomainEntry{}, id)
	if result.Error != nil {
		return fmt.Errorf("delete domain entry %d: %w", id, result.Error)
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

// --- BlockSettings (singleton) ---

func (s *ConfigStore) GetBlockSettings() (*BlockSettings, error) {
	var bs BlockSettings

	if err := s.db.FirstOrCreate(&bs, BlockSettings{ID: 1}).Error; err != nil {
		return nil, fmt.Errorf("get block settings: %w", err)
	}

	return &bs, nil
}

func (s *ConfigStore) PutBlockSettings(bs *BlockSettings) error {
	if _, err := time.ParseDuration(bs.BlockTTL); err != nil {
		return fmt.Errorf("invalid block TTL %q: %w", bs.BlockTTL, err)
	}

	bs.ID = 1

	if err := s.db.Save(bs).Error; err != nil {
		return fmt.Errorf("save block settings: %w", err)
	}

	return nil
}
