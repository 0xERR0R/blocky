package log

//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"golang.org/x/exp/maps"
)

const prefixField = "prefix"

// Logger is the global logging instance
//
//nolint:gochecknoglobals
var logger *logrus.Logger

// FormatType format for logging ENUM(
// text // logging as text
// json // JSON format
// )
type FormatType int

// Level log level ENUM(
// info
// trace
// debug
// warn
// error
// fatal
// )
type Level int

// Config defines all logging configurations
type Config struct {
	Level     Level      `yaml:"level" default:"info"`
	Format    FormatType `yaml:"format" default:"text"`
	Privacy   bool       `yaml:"privacy" default:"false"`
	Timestamp bool       `yaml:"timestamp" default:"true"`
}

//nolint:gochecknoinits
func init() {
	logger = logrus.New()

	defaultConfig := &Config{
		Level:     LevelInfo,
		Format:    FormatTypeText,
		Privacy:   false,
		Timestamp: true,
	}

	ConfigureLogger(defaultConfig)
}

// Log returns the global logger
func Log() *logrus.Logger {
	return logger
}

// PrefixedLog return the global logger with prefix
func PrefixedLog(prefix string) *logrus.Entry {
	return logger.WithField(prefixField, prefix)
}

// WithPrefix adds the given prefix to the logger.
func WithPrefix(logger *logrus.Entry, prefix string) *logrus.Entry {
	if existingPrefix, ok := logger.Data[prefixField]; ok {
		prefix = fmt.Sprintf("%s.%s", existingPrefix, prefix)
	}

	return logger.WithField(prefixField, prefix)
}

// EscapeInput removes line breaks from input
func EscapeInput(input string) string {
	result := strings.ReplaceAll(input, "\n", "")
	result = strings.ReplaceAll(result, "\r", "")

	return result
}

// ConfigureLogger applies configuration to the global logger
func ConfigureLogger(cfg *Config) {
	if level, err := logrus.ParseLevel(cfg.Level.String()); err != nil {
		logger.Fatalf("invalid log level %s %v", cfg.Level, err)
	} else {
		logger.SetLevel(level)
	}

	switch cfg.Format {
	case FormatTypeText:
		logFormatter := &prefixed.TextFormatter{
			TimestampFormat:  "2006-01-02 15:04:05",
			FullTimestamp:    true,
			ForceFormatting:  true,
			ForceColors:      false,
			QuoteEmptyFields: true,
			DisableTimestamp: !cfg.Timestamp,
		}

		logFormatter.SetColorScheme(&prefixed.ColorScheme{
			PrefixStyle:    "blue+b",
			TimestampStyle: "white+h",
		})

		logger.SetFormatter(logFormatter)

	case FormatTypeJson:
		logger.SetFormatter(&logrus.JSONFormatter{})
	}
}

// Silence disables the logger output
func Silence() {
	logger.Out = io.Discard
}

func WithIndent(log *logrus.Entry, prefix string, callback func(*logrus.Entry)) {
	undo := indentMessages(prefix, log.Logger)
	defer undo()

	callback(log)
}

// indentMessages modifies a logger and adds `prefix` to all messages.
//
// The returned function must be called to remove the prefix.
func indentMessages(prefix string, logger *logrus.Logger) func() {
	if _, ok := logger.Formatter.(*prefixed.TextFormatter); !ok {
		// log is not plaintext, do nothing
		return func() {}
	}

	oldHooks := maps.Clone(logger.Hooks)

	logger.AddHook(prefixMsgHook{
		prefix: prefix,
	})

	var once sync.Once

	return func() {
		once.Do(func() {
			logger.ReplaceHooks(oldHooks)
		})
	}
}

type prefixMsgHook struct {
	prefix string
}

// Levels implements `logrus.Hook`.
func (h prefixMsgHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire implements `logrus.Hook`.
func (h prefixMsgHook) Fire(entry *logrus.Entry) error {
	entry.Message = h.prefix + entry.Message

	return nil
}
