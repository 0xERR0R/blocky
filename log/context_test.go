package log

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestCtxWithFieldsAndFromCtx(t *testing.T) {
	var buf bytes.Buffer
	configureTo(&buf, &Config{Level: Level(slog.LevelInfo), Format: FormatTypeJson, Timestamp: true})

	ctx, l := CtxWithFields(context.Background(), slog.String("req_id", "r1"))
	l.InfoContext(ctx, "first")

	// A logger from the same ctx must also carry the field.
	FromCtx(ctx).InfoContext(ctx, "second")

	out := buf.String()
	if strings.Count(out, `"req_id":"r1"`) != 2 {
		t.Errorf("expected req_id on both lines, got: %s", out)
	}
}

// A ctx-bound logger must carry the request attrs even on the NON-Context emit
// methods (logger.Info/Debug/...), which slog dispatches with a background
// context. This is the regression that dropped req_id/client_ip from resolver
// logs after the slog migration.
func TestWithContextNonContextEmit(t *testing.T) {
	var buf bytes.Buffer
	configureTo(&buf, &Config{Level: Level(slog.LevelInfo), Format: FormatTypeJson, Timestamp: false})

	ctx, _ := CtxWithFields(context.Background(), slog.String("req_id", "r1"))

	// Plain Info (no *Context), exactly like the resolver call sites.
	WithContext(ctx, Log()).Info("plain")

	if out := buf.String(); strings.Count(out, `"req_id":"r1"`) != 1 {
		t.Errorf("expected req_id on the plain (non-context) line exactly once, got: %s", out)
	}
}

// Binding must not double-inject when the caller then uses a Context method
// (the bound handler replaces, not stacks on, the global contextHandler).
func TestWithContextNoDoubleInject(t *testing.T) {
	var buf bytes.Buffer
	configureTo(&buf, &Config{Level: Level(slog.LevelInfo), Format: FormatTypeJson, Timestamp: false})

	ctx, _ := CtxWithFields(context.Background(), slog.String("req_id", "r1"))

	WithContext(ctx, Log()).InfoContext(ctx, "ctx-method")

	if out := buf.String(); strings.Count(out, `"req_id":"r1"`) != 1 {
		t.Errorf("expected req_id exactly once (no double inject), got: %s", out)
	}
}
