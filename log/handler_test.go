package log

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestContextHandlerInjectsCtxAttrs(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(&contextHandler{next: base})

	ctx := ctxWithAttrs(context.Background(), slog.String("req_id", "abc"))

	logger.InfoContext(ctx, "hello")

	out := buf.String()
	if !strings.Contains(out, "req_id=abc") {
		t.Errorf("expected req_id in output, got: %s", out)
	}
	if !strings.Contains(out, "hello") {
		t.Errorf("expected message in output, got: %s", out)
	}
}

func TestContextHandlerLazyOnDisabledLevel(t *testing.T) {
	var resolved int
	valuer := slog.AnyValue(logValuerFunc(func() slog.Value {
		resolved++

		return slog.StringValue("expensive")
	}))

	var buf bytes.Buffer
	base := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(&contextHandler{next: base})

	ctx := ctxWithAttrs(context.Background(), slog.Attr{Key: "q", Value: valuer})

	logger.DebugContext(ctx, "should not emit") // Debug < Info => disabled

	if resolved != 0 {
		t.Errorf("LogValuer resolved %d times on disabled level, want 0", resolved)
	}
}

type logValuerFunc func() slog.Value

func (f logValuerFunc) LogValue() slog.Value { return f() }
