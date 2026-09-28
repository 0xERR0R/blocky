// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package configstore

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/0xERR0R/blocky/pkg/statscollector"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SaveStats persists a full stats snapshot to the database in a single transaction.
func (s *ConfigStore) SaveStats(snap *statscollector.StatsSnapshot) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Batch upsert buckets
		var bucketRows []StatsBucket
		for _, b := range snap.Buckets {
			if b.Total == 0 && b.Blocked == 0 {
				continue
			}

			cc, err := json.Marshal(b.ClientCounts)
			if err != nil {
				return fmt.Errorf("marshal client counts: %w", err)
			}

			bucketRows = append(bucketRows, StatsBucket{
				Timestamp:     b.Timestamp.Unix(),
				Total:         b.Total,
				Blocked:       b.Blocked,
				ClientCounts:  string(cc),
				LatencySum:    int64(b.LatencySum),
				UpstreamCount: b.UpstreamCount,
			})
		}

		if len(bucketRows) > 0 {
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "timestamp"}},
				DoUpdates: clause.AssignmentColumns([]string{"total", "blocked", "client_counts", "latency_sum", "upstream_count"}),
			}).CreateInBatches(&bucketRows, 50).Error; err != nil {
				return fmt.Errorf("upsert stats buckets: %w", err)
			}
		}

		// Batch upsert counters
		var counterRows []StatsCounter
		for category, m := range snap.Counters {
			for key, count := range m {
				counterRows = append(counterRows, StatsCounter{
					Category: category,
					Key:      key,
					Count:    count,
				})
			}
		}

		if len(counterRows) > 0 {
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "category"}, {Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"count"}),
			}).CreateInBatches(&counterRows, 50).Error; err != nil {
				return fmt.Errorf("upsert stats counters: %w", err)
			}
		}

		// Delete counter rows no longer present in the snapshot
		for category, m := range snap.Counters {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}

			if len(keys) > 0 {
				if err := tx.Where("category = ? AND key NOT IN ?", category, keys).
					Delete(&StatsCounter{}).Error; err != nil {
					return fmt.Errorf("prune stale counters for %s: %w", category, err)
				}
			} else {
				if err := tx.Where("category = ?", category).
					Delete(&StatsCounter{}).Error; err != nil {
					return fmt.Errorf("prune empty category %s: %w", category, err)
				}
			}
		}

		return nil
	})
}

// LoadStats reads the persisted stats snapshot from the database.
// Returns nil snapshot (no error) if no stats have been saved yet.
func (s *ConfigStore) LoadStats() (*statscollector.StatsSnapshot, error) {
	var bucketRows []StatsBucket
	if err := s.db.Find(&bucketRows).Error; err != nil {
		return nil, fmt.Errorf("load stats buckets: %w", err)
	}

	var counterRows []StatsCounter
	if err := s.db.Find(&counterRows).Error; err != nil {
		return nil, fmt.Errorf("load stats counters: %w", err)
	}

	if len(bucketRows) == 0 && len(counterRows) == 0 {
		return nil, nil
	}

	snap := &statscollector.StatsSnapshot{
		Counters: make(map[string]map[string]int),
	}

	for _, row := range bucketRows {
		b := statscollector.BucketSnapshot{
			Timestamp:     time.Unix(row.Timestamp, 0),
			Total:         row.Total,
			Blocked:       row.Blocked,
			LatencySum:    time.Duration(row.LatencySum),
			UpstreamCount: row.UpstreamCount,
		}

		if row.ClientCounts != "" && row.ClientCounts != "{}" {
			if err := json.Unmarshal([]byte(row.ClientCounts), &b.ClientCounts); err != nil {
				return nil, fmt.Errorf("unmarshal client counts: %w", err)
			}
		}

		snap.Buckets = append(snap.Buckets, b)
	}

	for _, row := range counterRows {
		if snap.Counters[row.Category] == nil {
			snap.Counters[row.Category] = make(map[string]int)
		}
		snap.Counters[row.Category][row.Key] = row.Count
	}

	return snap, nil
}

// PruneStatsBefore removes stats buckets older than the given time.
func (s *ConfigStore) PruneStatsBefore(t time.Time) error {
	if err := s.db.Where("timestamp < ?", t.Unix()).Delete(&StatsBucket{}).Error; err != nil {
		return fmt.Errorf("prune stats buckets: %w", err)
	}

	return nil
}
