package logstream

import (
	"time"

	"github.com/sirupsen/logrus"
)

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
