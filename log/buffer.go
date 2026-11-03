package log

import (
	"io"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Buffer holds what is logged to its entry, at any level, until Replay logs it to
// another logger. What is logged before that logger is set up still follows its
// level, format and target.
type Buffer struct {
	logger *logrus.Logger

	mu      sync.Mutex
	entries []bufferedEntry
}

type bufferedEntry struct {
	level   logrus.Level
	time    time.Time
	message string
	data    logrus.Fields
}

// NewBuffer returns an empty Buffer.
func NewBuffer() *Buffer {
	b := &Buffer{logger: logrus.New()}

	b.logger.SetLevel(logrus.TraceLevel)
	b.logger.SetFormatter(nopFormatter{}) // the target formats each entry on replay
	b.logger.SetOutput(io.Discard)
	b.logger.AddHook(b)

	return b
}

// Entry returns an entry logging to the buffer.
func (b *Buffer) Entry() *logrus.Entry {
	return logrus.NewEntry(b.logger)
}

// Levels implements `logrus.Hook`.
func (b *Buffer) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire implements `logrus.Hook`.
func (b *Buffer) Fire(entry *logrus.Entry) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries = append(b.entries, bufferedEntry{
		level:   entry.Level,
		time:    entry.Time,
		message: entry.Message,
		data:    entry.Data, // logrus hands each hook a copy
	})

	return nil
}

// Replay logs the held entries to logger, as far as its level allows, and empties
// the buffer.
func (b *Buffer) Replay(logger *logrus.Logger) {
	b.mu.Lock()
	entries := b.entries
	b.entries = nil
	b.mu.Unlock()

	for _, e := range entries {
		logger.WithFields(e.data).WithTime(e.time).Log(e.level, e.message)
	}
}
