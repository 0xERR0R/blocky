package configstore

import (
	"fmt"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type ConfigStore struct {
	db *gorm.DB
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

	if err := db.AutoMigrate(
		&ClientGroup{},
		&BlocklistSource{},
		&CustomDNSEntry{},
		&BlockSettings{},
		&DBMetadata{},
	); err != nil {
		return nil, fmt.Errorf("auto-migrate config tables: %w", err)
	}

	return &ConfigStore{db: db}, nil
}

func (s *ConfigStore) Close() error {
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

// PutClientGroup upserts a client group by name.
func (s *ConfigStore) PutClientGroup(g *ClientGroup) error {
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
