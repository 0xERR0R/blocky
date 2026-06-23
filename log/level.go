package log

import (
	"fmt"
	"log/slog"
	"strings"
)

// Level is blocky's log level. It wraps slog.Level but parses the historical
// (logrus) level strings from YAML so existing configs keep working.
type Level slog.Level

// ToSlogLevel returns the underlying slog.Level.
func (l Level) ToSlogLevel() slog.Level { return slog.Level(l) }

//nolint:gochecknoglobals
var levelByName = map[string]slog.Level{
	"trace":   slog.LevelDebug, // legacy alias: the dedicated trace level was removed; folds into debug
	"debug":   slog.LevelDebug,
	"info":    slog.LevelInfo,
	"warn":    slog.LevelWarn,
	"warning": slog.LevelWarn,
	"error":   slog.LevelError,
	"fatal":   slog.LevelError, // legacy: no code emits at fatal anymore
	"panic":   slog.LevelError, // legacy
}

// String returns the canonical lower-case level name. slog.Level.String()
// already yields "DEBUG"/"INFO"/"WARN"/"ERROR" (with "+N"/"-N" offsets for
// non-canonical levels), so lower-casing it gives blocky's canonical names that
// UnmarshalText round-trips, without a parallel name table to keep in sync.
func (l Level) String() string {
	return strings.ToLower(slog.Level(l).String())
}

// UnmarshalText implements encoding.TextUnmarshaler (used by the YAML loader,
// the same mechanism FormatType relies on).
func (l *Level) UnmarshalText(text []byte) error {
	name := strings.ToLower(strings.TrimSpace(string(text)))

	lvl, ok := levelByName[name]
	if !ok {
		return fmt.Errorf("invalid log level %q", string(text))
	}

	*l = Level(lvl)

	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (l Level) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}
