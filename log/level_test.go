package log

import (
	"log/slog"
	"testing"
)

func TestLevelUnmarshalText(t *testing.T) {
	cases := map[string]slog.Level{
		"trace":   slog.LevelDebug, // legacy alias folds into debug
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"fatal":   slog.LevelError,
		"panic":   slog.LevelError,
		"INFO":    slog.LevelInfo, // case-insensitive
	}
	for in, want := range cases {
		var l Level
		if err := l.UnmarshalText([]byte(in)); err != nil {
			t.Fatalf("UnmarshalText(%q) error: %v", in, err)
		}
		if l.ToSlogLevel() != want {
			t.Errorf("UnmarshalText(%q) = %v, want %v", in, l.ToSlogLevel(), want)
		}
	}

	var bad Level
	if err := bad.UnmarshalText([]byte("nonsense")); err == nil {
		t.Error("expected error for invalid level, got nil")
	}
}

func TestLevelStringRoundTrip(t *testing.T) {
	for _, name := range []string{"debug", "info", "warn", "error"} {
		var l Level
		if err := l.UnmarshalText([]byte(name)); err != nil {
			t.Fatal(err)
		}
		if l.String() != name {
			t.Errorf("String() = %q, want %q", l.String(), name)
		}
	}
}
