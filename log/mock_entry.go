package log

import (
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
)

func NewMockEntry() (*logrus.Entry, *MockLoggerHook) {
	logger, _ := test.NewNullLogger()
	logger.Level = logrus.TraceLevel

	entry := logrus.Entry{Logger: logger}
	hook := MockLoggerHook{}

	entry.Logger.AddHook(&hook)

	hook.On("Fire", mock.Anything).Return(nil)

	return &entry, &hook
}

type MockLoggerHook struct {
	mock.Mock

	Messages []string
	mu       sync.Mutex
}

// Levels implements `logrus.Hook`.
func (h *MockLoggerHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire implements `logrus.Hook`.
func (h *MockLoggerHook) Fire(entry *logrus.Entry) error {
	_ = h.Called()

	h.mu.Lock()
	defer h.mu.Unlock()

	h.Messages = append(h.Messages, entry.Message)

	return nil
}

// Reset clears the Messages slice, removing all logged messages.
// It is safe to call concurrently with other methods on MockLoggerHook,
// as all access to Messages is protected by a mutex.
func (h *MockLoggerHook) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.Messages = nil
}
