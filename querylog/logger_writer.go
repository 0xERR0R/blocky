package querylog

import (
	"context"
	"log/slog"
	"strings"

	"github.com/0xERR0R/blocky/log"
)

const loggerPrefixLoggerWriter = "queryLog"

type LoggerWriter struct {
	logger *slog.Logger
}

func NewLoggerWriter() *LoggerWriter {
	return &LoggerWriter{logger: log.PrefixedLog(loggerPrefixLoggerWriter)}
}

func (d *LoggerWriter) Write(entry *LogEntry) {
	d.logger.LogAttrs(context.Background(), slog.LevelInfo, "query resolved", LogEntryFields(entry)...)
}

func (d *LoggerWriter) CleanUp() {
	// Nothing to do
}

// LogEntryFields returns the entry as flat, snake_case slog attrs, omitting
// zero-valued fields (matching the historical logrus WithFields output).
func LogEntryFields(entry *LogEntry) []slog.Attr {
	return withoutZeroes(
		slog.String("client_ip", entry.ClientIP),
		slog.String("client_names", strings.Join(entry.ClientNames, "; ")),
		slog.String("response_reason", entry.ResponseReason),
		slog.String("response_type", entry.ResponseType),
		slog.String("response_code", entry.ResponseCode),
		slog.String("question_name", entry.QuestionName),
		slog.String("question_type", entry.QuestionType),
		slog.String("answer", entry.Answer),
		slog.Int64("duration_ms", entry.DurationMs),
		slog.String("instance", entry.BlockyInstance),
	)
}

func withoutZeroes(attrs ...slog.Attr) []slog.Attr {
	result := attrs[:0]

	for _, a := range attrs {
		if !isZeroValue(a.Value) {
			result = append(result, a)
		}
	}

	return result
}

// isZeroValue reports whether v holds the zero value for its kind. It switches
// on slog.Kind rather than using reflection so the per-query query-log path
// stays allocation-free and never panics on a nil interface value.
func isZeroValue(v slog.Value) bool {
	//nolint:exhaustive // the default branch intentionally treats every other kind as non-zero
	switch v.Kind() {
	case slog.KindString:
		return v.String() == ""
	case slog.KindInt64:
		return v.Int64() == 0
	case slog.KindUint64:
		return v.Uint64() == 0
	case slog.KindFloat64:
		return v.Float64() == 0
	case slog.KindBool:
		return !v.Bool()
	default:
		return false
	}
}
