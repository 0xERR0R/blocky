package log

import (
	"io"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

func NewMockEntry() (*logrus.Entry, *MockLoggerHook) {
	logger := logrus.New()
	logger.Out = io.Discard

	entry := logrus.Entry{Logger: logger}
	hook := MockLoggerHook{}

	entry.Logger.AddHook(&hook)

	hook.On("Fire", mock.Anything).Return(nil)

	return &entry, &hook
}

type MockLoggerHook struct {
	mock.Mock

	Messages []string
}

// Levels implements `logrus.Hook`.
func (h *MockLoggerHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire implements `logrus.Hook`.
func (h *MockLoggerHook) Fire(entry *logrus.Entry) error {
	_ = h.Called()

	h.Messages = append(h.Messages, entry.Message)

	return nil
}
