// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package configstore

import (
	"errors"
	"fmt"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"gorm.io/gorm"
)

const defaultUpstreamGroupName = "default"

// --- UpstreamGroup CRUD ---

func (s *ConfigStore) ListUpstreamGroups() ([]UpstreamGroup, error) {
	var groups []UpstreamGroup
	if err := s.db.Order("name").Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("list upstream groups: %w", err)
	}

	return groups, nil
}

func (s *ConfigStore) GetUpstreamGroup(name string) (*UpstreamGroup, error) {
	var g UpstreamGroup
	if err := s.db.Where("name = ?", name).First(&g).Error; err != nil {
		return nil, fmt.Errorf("get upstream group %q: %w", name, err)
	}

	return &g, nil
}

// PutUpstreamGroup upserts an upstream group by name.
// The Slug field is always regenerated from the Name.
func (s *ConfigStore) PutUpstreamGroup(g *UpstreamGroup) error {
	g.Slug = util.SanitizeGroupSlug(g.Name)
	if g.Slug == "" {
		return fmt.Errorf("upstream group name %q produces an empty slug", g.Name)
	}

	// Check for slug collision with a different group
	var collision UpstreamGroup
	if err := s.db.Where("slug = ? AND name != ?", g.Slug, g.Name).First(&collision).Error; err == nil {
		return fmt.Errorf("slug %q already used by upstream group %q", g.Slug, collision.Name)
	}

	var existing UpstreamGroup

	err := s.db.Where("name = ?", g.Name).First(&existing).Error
	if err == nil {
		g.ID = existing.ID
		g.CreatedAt = existing.CreatedAt

		if err := s.db.Save(g).Error; err != nil {
			return fmt.Errorf("update upstream group %q: %w", g.Name, err)
		}

		return nil
	}

	if err := s.db.Create(g).Error; err != nil {
		return fmt.Errorf("create upstream group %q: %w", g.Name, err)
	}

	return nil
}

// DeleteUpstreamGroup deletes a group by name. The "default" group cannot be deleted.
// All servers belonging to the group are also deleted.
func (s *ConfigStore) DeleteUpstreamGroup(name string) error {
	if name == defaultUpstreamGroupName {
		return errors.New("cannot delete the default upstream group")
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("group_name = ?", name).Delete(&UpstreamServer{}).Error; err != nil {
			return fmt.Errorf("delete upstream servers for group %q: %w", name, err)
		}

		result := tx.Where("name = ?", name).Delete(&UpstreamGroup{})
		if result.Error != nil {
			return fmt.Errorf("delete upstream group %q: %w", name, result.Error)
		}

		if result.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}

		return nil
	})
}

// --- UpstreamServer CRUD ---

func (s *ConfigStore) ListUpstreamServers(groupName string) ([]UpstreamServer, error) {
	q := s.db.Order("position, id")

	if groupName != "" {
		q = q.Where("group_name = ?", groupName)
	}

	var servers []UpstreamServer
	if err := q.Find(&servers).Error; err != nil {
		return nil, fmt.Errorf("list upstream servers: %w", err)
	}

	return servers, nil
}

func (s *ConfigStore) GetUpstreamServer(id uint) (*UpstreamServer, error) {
	var srv UpstreamServer
	if err := s.db.First(&srv, id).Error; err != nil {
		return nil, fmt.Errorf("get upstream server %d: %w", id, err)
	}

	return &srv, nil
}

func (s *ConfigStore) CreateUpstreamServer(srv *UpstreamServer) error {
	// Ensure the parent group exists
	if _, err := s.GetUpstreamGroup(srv.GroupName); err != nil {
		return fmt.Errorf("upstream group %q does not exist: %w", srv.GroupName, err)
	}

	if err := s.db.Create(srv).Error; err != nil {
		return fmt.Errorf("create upstream server: %w", err)
	}

	return nil
}

func (s *ConfigStore) UpdateUpstreamServer(srv *UpstreamServer) error {
	if err := s.db.Save(srv).Error; err != nil {
		return fmt.Errorf("update upstream server %d: %w", srv.ID, err)
	}

	return nil
}

func (s *ConfigStore) DeleteUpstreamServer(id uint) error {
	// Prevent deleting the last server in the default group
	var srv UpstreamServer
	if err := s.db.First(&srv, id).Error; err != nil {
		return fmt.Errorf("get upstream server %d: %w", id, err)
	}

	if srv.GroupName == defaultUpstreamGroupName {
		var count int64
		if err := s.db.Model(&UpstreamServer{}).
			Where("group_name = ?", defaultUpstreamGroupName).
			Count(&count).Error; err != nil {
			return fmt.Errorf("count default upstream servers: %w", err)
		}

		if count <= 1 {
			return errors.New("cannot delete the last server in the default upstream group")
		}
	}

	result := s.db.Delete(&UpstreamServer{}, id)
	if result.Error != nil {
		return fmt.Errorf("delete upstream server %d: %w", id, result.Error)
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

// --- UpstreamSettings (singleton) ---

func (s *ConfigStore) GetUpstreamSettings() (*UpstreamSettings, error) {
	var us UpstreamSettings

	if err := s.db.FirstOrCreate(&us, UpstreamSettings{ID: 1}).Error; err != nil {
		return nil, fmt.Errorf("get upstream settings: %w", err)
	}

	// Apply defaults for any empty fields (covers pre-existing rows)
	changed := false

	if us.Strategy == "" {
		us.Strategy = "parallel_best"
		changed = true
	}

	if us.Timeout == "" {
		us.Timeout = "2s"
		changed = true
	}

	if us.InitStrategy == "" {
		us.InitStrategy = "blocking"
		changed = true
	}

	if changed {
		if err := s.db.Save(&us).Error; err != nil {
			return nil, fmt.Errorf("save defaulted upstream settings: %w", err)
		}
	}

	return &us, nil
}

func (s *ConfigStore) PutUpstreamSettings(us *UpstreamSettings) error {
	if _, err := config.ParseUpstreamStrategy(us.Strategy); err != nil {
		return fmt.Errorf("invalid upstream strategy %q: %w", us.Strategy, err)
	}

	if _, err := config.ParseInitStrategy(us.InitStrategy); err != nil {
		return fmt.Errorf("invalid init strategy %q: %w", us.InitStrategy, err)
	}

	if _, err := time.ParseDuration(us.Timeout); err != nil {
		return fmt.Errorf("invalid timeout %q: %w", us.Timeout, err)
	}

	us.ID = 1

	if err := s.db.Save(us).Error; err != nil {
		return fmt.Errorf("save upstream settings: %w", err)
	}

	return nil
}

// --- Seeding ---

// seedDefaultUpstreams inserts a "default" group with 1.1.1.1 and 1.0.0.1 and a
// default UpstreamSettings row if no upstream groups currently exist.
func (s *ConfigStore) seedDefaultUpstreams() error {
	var count int64
	if err := s.db.Model(&UpstreamGroup{}).Count(&count).Error; err != nil {
		return fmt.Errorf("count upstream groups: %w", err)
	}

	if count == 0 {
		g := &UpstreamGroup{Name: defaultUpstreamGroupName}
		if err := s.PutUpstreamGroup(g); err != nil {
			return fmt.Errorf("create default upstream group: %w", err)
		}

		defaults := []string{"1.1.1.1", "1.0.0.1"}
		for i, url := range defaults {
			srv := &UpstreamServer{
				GroupName: defaultUpstreamGroupName,
				URL:       url,
				Position:  i,
				Enabled:   new(true),
			}
			if err := s.db.Create(srv).Error; err != nil {
				return fmt.Errorf("seed default upstream %q: %w", url, err)
			}
		}
	}

	// Ensure settings row exists with defaults
	if _, err := s.GetUpstreamSettings(); err != nil {
		return err
	}

	return nil
}

// --- BuildUpstreamsConfig ---

// BuildUpstreamsConfig replaces the dynamic fields of base (groups + global
// settings) with DB state while preserving YAML-only fields that resolvers
// expect (none currently, but kept for symmetry with BuildBlockingConfig).
// Upstream URLs are parsed via config.ParseUpstream so all existing validation
// (DNS stamps, commonName, cert fingerprints, etc.) is reused.
func (s *ConfigStore) BuildUpstreamsConfig(base config.Upstreams) (config.Upstreams, error) {
	groups, err := s.ListUpstreamGroups()
	if err != nil {
		return base, fmt.Errorf("load upstream groups: %w", err)
	}

	servers, err := s.ListUpstreamServers("")
	if err != nil {
		return base, fmt.Errorf("load upstream servers: %w", err)
	}

	settings, err := s.GetUpstreamSettings()
	if err != nil {
		return base, fmt.Errorf("load upstream settings: %w", err)
	}

	// Apply settings
	strategy, err := config.ParseUpstreamStrategy(settings.Strategy)
	if err != nil {
		return base, fmt.Errorf("invalid upstream strategy %q: %w", settings.Strategy, err)
	}

	initStrategy, err := config.ParseInitStrategy(settings.InitStrategy)
	if err != nil {
		return base, fmt.Errorf("invalid init strategy %q: %w", settings.InitStrategy, err)
	}

	timeout, err := time.ParseDuration(settings.Timeout)
	if err != nil {
		return base, fmt.Errorf("invalid upstream timeout %q: %w", settings.Timeout, err)
	}

	base.Strategy = strategy
	base.Init.Strategy = initStrategy
	base.Timeout = config.Duration(timeout)
	base.UserAgent = settings.UserAgent

	// Index servers by group for ordered assembly
	byGroup := make(map[string][]UpstreamServer, len(groups))
	for _, srv := range servers {
		if !srv.IsEnabled() {
			continue
		}

		byGroup[srv.GroupName] = append(byGroup[srv.GroupName], srv)
	}

	out := make(config.UpstreamGroups, len(groups))

	for _, g := range groups {
		list := byGroup[g.Name]

		parsed := make([]config.Upstream, 0, len(list))

		for _, srv := range list {
			u, parseErr := config.ParseUpstream(srv.URL)
			if parseErr != nil {
				return base, fmt.Errorf("parse upstream %q in group %q: %w", srv.URL, g.Name, parseErr)
			}

			parsed = append(parsed, u)
		}

		out[g.Name] = parsed
	}

	base.Groups = out

	return base, nil
}
