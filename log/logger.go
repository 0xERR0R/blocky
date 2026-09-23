package log

//go:generate go tool go-enum -f=$GOFILE --marshal --names --template ../tools/schemagen/templates/enum_description.tmpl

import (
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/creasty/defaults"
	"github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
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
// text // Human-readable text.
// json // Structured JSON.
// )
type FormatType int

// TargetType destination for logging ENUM(
// stdout // Standard output.
// stderr // Standard error.
// syslog // System log, each entry at the priority matching its level.
// )
type TargetType int

// Config defines all logging configurations
type Config struct {
	Level     logrus.Level `default:"info"   yaml:"level"`
	Format    FormatType   `default:"text"   yaml:"format"`
	Target    TargetType   `default:"stdout" yaml:"target"`
	Syslog    SyslogConfig `yaml:"syslog"`
	Privacy   bool         `default:"false"  yaml:"privacy"`
	Timestamp bool         `default:"true"   yaml:"timestamp"`
}

// SyslogConfig defines where and as what blocky logs when the target is syslog
type SyslogConfig struct {
	// Network is empty for the local syslog socket, otherwise "udp" or "tcp"
	Network  string `default:""       yaml:"network"`
	Address  string `default:""       yaml:"address"`
	Tag      string `default:"blocky" yaml:"tag"`
	Facility string `default:"daemon" yaml:"facility"`
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

// SetPrefix sets prefix as the logger's prefix, replacing any prefix it already
// carries. Use this to give each resolver its own prefix without accumulating the
// prefixes of resolvers earlier in the chain. Contrast with WithPrefix, which
// appends to build a dotted chain (a.b.c).
func SetPrefix(logger *logrus.Entry, prefix string) *logrus.Entry {
	return logger.WithField(prefixField, prefix)
}

// WithPrefix adds the given prefix to the logger.
func WithPrefix(logger *logrus.Entry, prefix string) *logrus.Entry {
	// avoid fmt.Sprintf here: this runs once per resolver per request on the hot path,
	// and the values are plain strings, so a direct concat skips the interface boxing
	// and format-string parsing.
	if existingPrefix, ok := logger.Data[prefixField].(string); ok {
		prefix = existingPrefix + "." + prefix
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

	toSyslog := cfg.Target == TargetTypeSyslog

	formatter := newFormatter(cfg, toSyslog)
	logger.SetFormatter(formatter)

	if !toSyslog {
		logger.SetOutput(newOutput(cfg.Target))

		return
	}

	hook, err := newSyslogHook(cfg.Syslog, formatter)
	if err != nil {
		logger.SetOutput(newOutput(TargetTypeStderr))
		logger.Errorf("can't log to syslog, using stderr instead: %v", err)

		return
	}

	// the hook does the writing, so the stream itself receives nothing
	logger.SetOutput(io.Discard)
	logger.ReplaceHooks(logrus.LevelHooks{})
	logger.AddHook(hook)
}

// newFormatter returns the formatter for the configured format.
func newFormatter(cfg *Config, toSyslog bool) logrus.Formatter {
	if cfg.Format == FormatTypeJson {
		return &logrus.JSONFormatter{}
	}

	if toSyslog {
		return syslogFormatter{}
	}

	logFormatter := &prefixed.TextFormatter{
		TimestampFormat:  "2006-01-02 15:04:05",
		FullTimestamp:    true,
		ForceFormatting:  true,
		ForceColors:      false,
		QuoteEmptyFields: true,
		DisableTimestamp: !cfg.Timestamp,
		DisableColors:    noColor(),
	}

	logFormatter.SetColorScheme(&prefixed.ColorScheme{
		PrefixStyle:    "blue+b",
		TimestampStyle: "white+h",
	})

	return logFormatter
}

// syslogFormatter renders an entry as plain text carrying neither timestamp nor
// level: syslog records both itself, in the record's own header and priority.
type syslogFormatter struct{}

// Format implements `logrus.Formatter`.
func (syslogFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var out strings.Builder

	if prefix, ok := entry.Data[prefixField].(string); ok && prefix != "" {
		out.WriteString(prefix)
		out.WriteString(": ")
	}

	out.WriteString(entry.Message)

	fields := make([]string, 0, len(entry.Data))

	for field := range entry.Data {
		if field != prefixField {
			fields = append(fields, field)
		}
	}

	slices.Sort(fields)

	for _, field := range fields {
		fmt.Fprintf(&out, " %s=%v", field, entry.Data[field])
	}

	out.WriteString("\n")

	return []byte(out.String()), nil
}

func newOutput(target TargetType) io.Writer {
	if target == TargetTypeStderr {
		if noColor() {
			return os.Stderr
		}

		return colorable.NewColorableStderr()
	}

	if noColor() {
		return os.Stdout
	}

	// Windows does not support ANSI colors
	return colorable.NewColorableStdout()
}

// Respect NO_COLOR env var (https://no-color.org/)
func noColor() bool {
	return os.Getenv("NO_COLOR") != ""
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
	switch logger.Formatter.(type) {
	case *prefixed.TextFormatter, syslogFormatter:
	default:
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
