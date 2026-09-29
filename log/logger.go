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
	Network  string         `default:""       yaml:"network"`
	Address  string         `default:""       yaml:"address"`
	Tag      string         `default:"blocky" yaml:"tag"`
	Facility SyslogFacility `default:"daemon" yaml:"facility"`
}

// SyslogFacility is the facility used for syslog messages. ENUM(
// daemon // System daemon messages.
// user // User-level messages.
// local0 // Local use facility 0.
// local1 // Local use facility 1.
// local2 // Local use facility 2.
// local3 // Local use facility 3.
// local4 // Local use facility 4.
// local5 // Local use facility 5.
// local6 // Local use facility 6.
// local7 // Local use facility 7.
// )
type SyslogFacility string

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

	if cfg.Target != TargetTypeSyslog {
		setOutput(logger, newFormatter(cfg), newOutput(cfg.Target))

		return
	}

	writer, err := newSyslogWriter(cfg.Syslog)
	if err != nil {
		setOutput(logger, newFormatter(cfg), newOutput(TargetTypeStderr))
		logger.Errorf("can't log to syslog, using stderr instead: %v", err)

		return
	}

	setOutput(logger, levelFormatter{newSyslogFormatter(cfg)}, writer)
}

// syslogOutput is a logger output writing to syslog, which must be closed once
// the logger no longer writes to it.
type syslogOutput interface {
	io.Writer
	closeSyslog() error
}

// setOutput points logger at formatter and out, then closes the syslog output it
// replaces. logrus writes to Out under the lock SetOutput takes, so nothing writes
// to the old output once SetOutput has returned. An entry formatted for the old
// output but written to the new one while switching is logged either way.
func setOutput(logger *logrus.Logger, formatter logrus.Formatter, out io.Writer) {
	old := logger.Out

	logger.SetFormatter(formatter)
	logger.SetOutput(out)

	if oldSyslog, ok := old.(syslogOutput); ok && old != out {
		_ = oldSyslog.closeSyslog()
	}
}

// newFormatter returns the formatter for the configured format.
func newFormatter(cfg *Config) logrus.Formatter {
	if cfg.Format == FormatTypeJson {
		return &logrus.JSONFormatter{}
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

// newSyslogFormatter returns the formatter for the configured format when logging
// to syslog.
func newSyslogFormatter(cfg *Config) logrus.Formatter {
	if cfg.Format == FormatTypeJson {
		return &logrus.JSONFormatter{}
	}

	return syslogFormatter{}
}

// levelMarker starts a formatted entry carrying its level, see levelFormatter.
const levelMarker = 0

// levelFormatter prefixes each entry with a marker and its level, so the syslog
// writer can pick the record's priority and strip both again. The writer only
// sees bytes, and logrus formats an entry after all hooks have run, so this is
// the last point that still knows the entry's final message and level.
type levelFormatter struct {
	logrus.Formatter
}

// Format implements `logrus.Formatter`.
func (f levelFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	line, err := f.Formatter.Format(entry)
	if err != nil {
		return nil, err
	}

	return append([]byte{levelMarker, byte(entry.Level)}, line...), nil //nolint:gosec // levels are 0-6
}

// splitLevel returns the level levelFormatter prefixed to p, and the rest of p.
// Without the prefix, the entry is logged at info.
func splitLevel(p []byte) (logrus.Level, []byte) {
	if len(p) >= 2 && p[0] == levelMarker {
		return logrus.Level(p[1]), p[2:]
	}

	return logrus.InfoLevel, p
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
	formatter := logger.Formatter
	if level, ok := formatter.(levelFormatter); ok {
		formatter = level.Formatter
	}

	switch formatter.(type) {
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
