package configstore

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

type ClientGroup struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	Name      string     `gorm:"uniqueIndex;not null" json:"name"`
	Clients   StringList `gorm:"type:text;not null;default:'[]'" json:"clients"`
	Groups    StringList `gorm:"type:text;not null;default:'[]'" json:"groups"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type BlocklistSource struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	GroupName  string    `gorm:"index;not null" json:"group_name"`
	ListType   string    `gorm:"not null" json:"list_type"`
	SourceType string    `gorm:"not null" json:"source_type"`
	Source     string    `gorm:"not null" json:"source"`
	Enabled    *bool     `gorm:"not null;default:true" json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type CustomDNSEntry struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Domain     string    `gorm:"uniqueIndex:idx_dns_unique;not null" json:"domain"`
	RecordType string    `gorm:"uniqueIndex:idx_dns_unique;not null" json:"record_type"`
	Value      string    `gorm:"uniqueIndex:idx_dns_unique;not null" json:"value"`
	TTL        uint32    `gorm:"not null;default:3600" json:"ttl"`
	Enabled    *bool     `gorm:"not null;default:true" json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type BlockSettings struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	BlockType string    `gorm:"not null;default:'ZEROIP'" json:"block_type"`
	BlockTTL  string    `gorm:"not null;default:'6h'" json:"block_ttl"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DBMetadata tracks one-time operations like seeding.
type DBMetadata struct {
	Key   string `gorm:"primaryKey"`
	Value string
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

func (s *StringList) Scan(value interface{}) error {
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

// BoolPtr returns a pointer to a bool value.
func BoolPtr(b bool) *bool { return &b }

// IsEnabled returns the Enabled value, defaulting to true if nil.
func (s *BlocklistSource) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// IsEnabled returns the Enabled value, defaulting to true if nil.
func (e *CustomDNSEntry) IsEnabled() bool { return e.Enabled == nil || *e.Enabled }
