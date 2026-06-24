package log

//go:generate go tool go-enum -f=$GOFILE --marshal --names --template ../tools/schemagen/templates/enum_description.tmpl

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/creasty/defaults"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
)

const (
	prefixKey      = "prefix"
	textTimeLayout = "2006-01-02 15:04:05"
)

// FormatType format for logging ENUM(
// text // Human-readable text.
// json // Structured JSON.
// )
type FormatType int

// Config defines all logging configuration.
type Config struct {
	Level     Level      `default:"info"  yaml:"level"`
	Format    FormatType `default:"text"  yaml:"format"`
	Privacy   bool       `default:"false" yaml:"privacy"`
	Timestamp bool       `default:"true"  yaml:"timestamp"`
}

// DefaultConfig returns a Config initialized with default values.
func DefaultConfig() *Config {
	cfg := new(Config)
	defaults.MustSet(cfg)

	return cfg
}

//nolint:gochecknoglobals
var levelVar = new(slog.LevelVar)

//nolint:gochecknoinits
func init() {
	setLogger(newLogger(os.Stdout, DefaultConfig()))
}

// setLogger installs l as the slog default. Readers (Log/PrefixedLog/FromCtx)
// read slog.Default(), which slog updates atomically, so a hot-path reader
// never races with a Configure/Silence/CaptureGlobal swap.
func setLogger(l *slog.Logger) {
	slog.SetDefault(l)
}

// Log returns the global logger.
func Log() *slog.Logger { return slog.Default() }

// SetLevel changes the active log level at runtime.
func SetLevel(l slog.Level) { levelVar.Set(l) }

// Configure applies cfg to the global logger (writing to os.Stdout).
func Configure(cfg *Config) { configureTo(os.Stdout, cfg) }

// configureTo is the test seam: it builds the global logger writing to w.
func configureTo(w io.Writer, cfg *Config) {
	levelVar.Set(cfg.Level.ToSlogLevel())
	setLogger(newLogger(w, cfg))
}

// newLogger builds a slog logger for cfg writing to w, wrapped in the
// contextHandler so request-scoped attrs are injected lazily.
func newLogger(w io.Writer, cfg *Config) *slog.Logger {
	var base slog.Handler

	switch cfg.Format {
	case FormatTypeJson:
		base = slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level:       levelVar,
			ReplaceAttr: replaceAttr(cfg),
		})
	case FormatTypeText:
		fallthrough
	default:
		base = tint.NewHandler(textWriter(w), &tint.Options{
			Level:       levelVar,
			TimeFormat:  textTimeLayout,
			NoColor:     noColor(w),
			ReplaceAttr: replaceAttr(cfg),
		})
	}

	return slog.New(&contextHandler{next: base})
}

// textWriter wraps os.Stdout with go-colorable for Windows ANSI support; other
// writers (tests, files) are returned unchanged.
func textWriter(w io.Writer) io.Writer {
	if w == os.Stdout {
		return colorable.NewColorableStdout()
	}

	return w
}

// noColor preserves blocky's historical behavior: disable color when NO_COLOR
// is set OR stdout is not a TTY. tint does not check NO_COLOR itself.
func noColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return true
	}

	if f, ok := w.(*os.File); ok {
		return !isatty.IsTerminal(f.Fd())
	}

	return true // non-file writer (tests, pipes) => no color
}

// replaceAttr drops the time attr when timestamps are disabled.
func replaceAttr(cfg *Config) func([]string, slog.Attr) slog.Attr {
	noTimestamp := !cfg.Timestamp

	return func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) != 0 {
			return a
		}

		if a.Key == slog.TimeKey && noTimestamp {
			return slog.Attr{}
		}

		return a
	}
}

// PrefixedLog returns the global logger tagged with a prefix attr.
func PrefixedLog(prefix string) *slog.Logger {
	return slog.Default().With(slog.String(prefixKey, prefix))
}

//nolint:gochecknoglobals
var inputEscaper = strings.NewReplacer("\n", "", "\r", "")

// EscapeInput removes line breaks from input (log-injection hardening).
func EscapeInput(input string) string {
	return inputEscaper.Replace(input)
}

// Silence discards all log output. Prefer ConfigureForTest(GinkgoWriter) in
// Ginkgo suites; Silence remains for non-Ginkgo callers.
func Silence() {
	setLogger(slog.New(slog.DiscardHandler))
}

// AttrError returns a standard attr for an error value.
func AttrError(err error) slog.Attr { return slog.Any("error", err) }
