package log

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestWithIndentPrefixesMessages(t *testing.T) {
	var buf bytes.Buffer
	configureTo(&buf, &Config{Level: Level(slog.LevelInfo), Format: FormatTypeText, Timestamp: false})

	WithIndent(Log(), "  ", func(l *slog.Logger) {
		l.InfoContext(context.Background(), "indented line")
	})

	if !strings.Contains(buf.String(), "  indented line") {
		t.Errorf("expected indented message, got: %q", buf.String())
	}
}
