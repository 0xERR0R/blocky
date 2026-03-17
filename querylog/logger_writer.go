package querylog

import (
	"reflect"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/logstream"
	"github.com/sirupsen/logrus"
)

const loggerPrefixLoggerWriter = "queryLog"

type LoggerWriter struct {
	logger      *logrus.Entry
	broadcaster *logstream.Broadcaster
}

func NewLoggerWriter() *LoggerWriter {
	return &LoggerWriter{logger: log.PrefixedLog(loggerPrefixLoggerWriter)}
}

// SetBroadcaster sets the logstream broadcaster for direct WebSocket publishing.
// When set, query log entries are published directly to the broadcaster,
// bypassing the logrus hook's map copy to reduce allocation pressure.
func (d *LoggerWriter) SetBroadcaster(b *logstream.Broadcaster) {
	d.broadcaster = b
}

func (d *LoggerWriter) Write(entry *LogEntry) {
	fields := LogEntryFields(entry)

	// Publish directly to broadcaster (avoids logrus hook's fields map copy)
	if d.broadcaster != nil {
		anyFields := make(map[string]any, len(fields))
		for k, v := range fields {
			anyFields[k] = v
		}

		d.broadcaster.Publish(logstream.LogEntry{
			Timestamp: entry.Start.UTC().Truncate(time.Millisecond),
			Level:     "info",
			Message:   "query resolved",
			Fields:    anyFields,
		})

		// Mark so the logrus hook skips this entry (prevent double-broadcast)
		fields[logstream.SkipHookField] = true
	}

	d.logger.WithFields(fields).Infof("query resolved")
}

func (d *LoggerWriter) CleanUp() {
	// Nothing to do
}

func LogEntryFields(entry *LogEntry) logrus.Fields {
	return withoutZeroes(logrus.Fields{
		"client_ip":       entry.ClientIP,
		"client_names":    strings.Join(entry.ClientNames, "; "),
		"response_reason": entry.ResponseReason,
		"response_type":   entry.ResponseType,
		"response_code":   entry.ResponseCode,
		"question_name":   entry.QuestionName,
		"question_type":   entry.QuestionType,
		"answer":          entry.Answer,
		"duration_ms":     entry.DurationMs,
		"instance":        entry.BlockyInstance,
	})
}

func withoutZeroes(fields logrus.Fields) logrus.Fields {
	for k, v := range fields {
		if reflect.ValueOf(v).IsZero() {
			delete(fields, k)
		}
	}

	return fields
}
