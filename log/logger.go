package log

//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/creasty/defaults"
	"github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"golang.org/x/exp/maps"
)

const prefixField = "prefix"

// Logger is the global logging instance
//
//nolint:gochecknoglobals
var (
	logger   *logrus.Logger
	initDone atomic.Bool
)

// FormatType format for logging ENUM(
// text // logging as text
// json // JSON format
// )
type FormatType int

// Config defines all logging configurations
type Config struct {
	Level     logrus.Level `yaml:"level" default:"info"`
	Format    FormatType   `yaml:"format" default:"text"`
	Privacy   bool         `yaml:"privacy" default:"false"`
	Timestamp bool         `yaml:"timestamp" default:"true"`
}

// DefaultConfig returns a new Config initialized with default values.
func DefaultConfig() *Config {
	cfg := new(Config)

	defaults.MustSet(cfg)

	return cfg
}

//nolint:gochecknoinits
func init() {
	if !initDone.CompareAndSwap(false, true) {
		return
	}

	newLogger := logrus.New()

	ConfigureLogger(newLogger, DefaultConfig())

	logger = newLogger
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

// Configure applies configuration to the global logger.
func Configure(cfg *Config) {
	ConfigureLogger(logger, cfg)
}

// Configure applies configuration to the given logger.
func ConfigureLogger(logger *logrus.Logger, cfg *Config) {
	logger.SetLevel(cfg.Level)

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

		// Windows does not support ANSI colors
		logger.SetOutput(colorable.NewColorableStdout())

	case FormatTypeJson:
		logger.SetFormatter(&logrus.JSONFormatter{})
	}
}

// Silence disables the logger output
func Silence() {
	initDone.Store(true)

	logger = logrus.New()

	logger.SetFormatter(nopFormatter{}) // skip expensive formatting

	// not actually needed but doesn't hurt
	logger.SetOutput(io.Discard)
}

type nopFormatter struct{}

func (f nopFormatter) Format(*logrus.Entry) ([]byte, error) {
	return nil, nil
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
