// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package logstream

import (
	"time"

	"github.com/sirupsen/logrus"
)

// SkipHookField is a logrus field key that, when present, causes the
// logstream hook to skip broadcasting the entry. Used by writers that
// publish directly to the broadcaster to avoid double-broadcasting.
const SkipHookField = "_logstream_skip"

type Hook struct {
	broadcaster *Broadcaster
}

func NewHook(broadcaster *Broadcaster) *Hook {
	return &Hook{broadcaster: broadcaster}
}

func (h *Hook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *Hook) Fire(entry *logrus.Entry) error {
	if _, skip := entry.Data[SkipHookField]; skip {
		return nil
	}

	fields := make(map[string]any, len(entry.Data))
	for k, v := range entry.Data {
		fields[k] = v
	}

	h.broadcaster.Publish(LogEntry{
		Timestamp: entry.Time.UTC().Truncate(time.Millisecond),
		Level:     entry.Level.String(),
		Message:   entry.Message,
		Fields:    fields,
	})

	return nil
}
