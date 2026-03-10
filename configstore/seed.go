package configstore

import (
	"fmt"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/miekg/dns"
)

const seededKey = "seeded"

// SeedFromConfig migrates YAML dynamic sections into the DB on first run.
// Subsequent calls are no-ops (guarded by a metadata flag).
func (s *ConfigStore) SeedFromConfig(cfg *config.Config) error {
	var meta DBMetadata
	if err := s.db.Where("key = ?", seededKey).First(&meta).Error; err == nil {
		return nil // already seeded
	}

	if err := s.seedBlocking(&cfg.Blocking); err != nil {
		return fmt.Errorf("seed blocking: %w", err)
	}

	if err := s.seedCustomDNS(&cfg.CustomDNS); err != nil {
		return fmt.Errorf("seed custom DNS: %w", err)
	}

	// Mark as seeded
	return s.db.Create(&DBMetadata{Key: seededKey, Value: "true"}).Error
}

func (s *ConfigStore) seedBlocking(b *config.Blocking) error {
	// Client groups
	for name, groups := range b.ClientGroupsBlock {
		// Collect client patterns from the group name itself
		// In YAML, key is a comma-separated list of client identifiers
		clients := StringList{name}

		g := ClientGroup{
			Name:    name,
			Clients: clients,
			Groups:  StringList(groups),
		}

		if err := s.db.Create(&g).Error; err != nil {
			return fmt.Errorf("seed client group %q: %w", name, err)
		}
	}

	// Denylists
	if err := s.seedSources(b.Denylists, "deny"); err != nil {
		return err
	}

	// Allowlists
	if err := s.seedSources(b.Allowlists, "allow"); err != nil {
		return err
	}

	// Block settings
	bs := BlockSettings{
		ID:        1,
		BlockType: b.BlockType,
		BlockTTL:  time.Duration(b.BlockTTL).String(),
	}

	return s.db.Create(&bs).Error
}

func (s *ConfigStore) seedSources(lists map[string][]config.BytesSource, listType string) error {
	for groupName, sources := range lists {
		for _, src := range sources {
			entry := BlocklistSource{
				GroupName:  groupName,
				ListType:   listType,
				SourceType: src.Type.String(),
				Source:     src.From,
				Enabled:    BoolPtr(true),
			}

			if err := s.db.Create(&entry).Error; err != nil {
				return fmt.Errorf("seed %s source for group %q: %w", listType, groupName, err)
			}
		}
	}

	return nil
}

func (s *ConfigStore) seedCustomDNS(c *config.CustomDNS) error {
	for domain, entries := range c.Mapping {
		for _, rr := range entries {
			entry, err := rrToEntry(domain, rr)
			if err != nil {
				return fmt.Errorf("seed custom DNS %q: %w", domain, err)
			}

			if err := s.db.Create(&entry).Error; err != nil {
				return fmt.Errorf("seed custom DNS entry for %q: %w", domain, err)
			}
		}
	}

	return nil
}

func rrToEntry(domain string, rr dns.RR) (CustomDNSEntry, error) {
	entry := CustomDNSEntry{
		Domain:  domain,
		TTL:     rr.Header().Ttl,
		Enabled: BoolPtr(true),
	}

	switch v := rr.(type) {
	case *dns.A:
		entry.RecordType = "A"
		entry.Value = v.A.String()
	case *dns.AAAA:
		entry.RecordType = "AAAA"
		entry.Value = v.AAAA.String()
	case *dns.CNAME:
		entry.RecordType = "CNAME"
		entry.Value = v.Target
	default:
		return entry, fmt.Errorf("unsupported record type %T", rr)
	}

	return entry, nil
}
