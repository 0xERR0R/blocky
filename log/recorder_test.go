package log

import (
	"context"
	"log/slog"
	"testing"
)

func TestRecorderCapturesMessages(t *testing.T) {
	logger, rec := NewRecorder()

	logger.Info("first")
	logger.Warn("second", slog.String("k", "v"))

	if got := rec.Messages(); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("Messages() = %v", got)
	}
	if rec.LastMessage() != "second" {
		t.Errorf("LastMessage() = %q", rec.LastMessage())
	}

	rec.Reset()
	if len(rec.Messages()) != 0 {
		t.Error("Reset did not clear messages")
	}
}

func TestRecorderWithAttrsVisible(t *testing.T) {
	logger, rec := NewRecorder()

	logger.With(slog.String("prefix", "blk")).Info("m")

	if got := rec.LastMessage(); got != "m" {
		t.Fatalf("LastMessage() = %q, want %q", got, "m")
	}

	val, ok := rec.Attr("prefix")
	if !ok {
		t.Fatal("Attr(\"prefix\") not found")
	}

	if got := val.String(); got != "blk" {
		t.Errorf("Attr(\"prefix\") = %q, want %q", got, "blk")
	}
}

func TestRecorderWithGroupNests(t *testing.T) {
	logger, rec := NewRecorder()

	logger.WithGroup("dns").Info("m", slog.String("rcode", "NXDOMAIN"))

	// The grouped attr must be nested, mirroring the real handlers, so the
	// top-level "rcode" key is absent and "dns" holds a group.
	if _, ok := rec.Attr("rcode"); ok {
		t.Error("expected rcode to be nested under the group, not top-level")
	}

	val, ok := rec.Attr("dns")
	if !ok {
		t.Fatal("Attr(\"dns\") group not found")
	}

	if val.Kind() != slog.KindGroup {
		t.Fatalf("expected dns to be a group, got %v", val.Kind())
	}
}

func TestRecorderWithGroupMergesAttrs(t *testing.T) {
	logger, rec := NewRecorder()

	// A WithAttrs attr and a per-call attr under the same group must land in a
	// SINGLE merged group, like the real text/JSON handlers (not two "g" attrs).
	logger.WithGroup("g").With(slog.Int("a", 1)).Info("m", slog.Int("b", 2))

	val, ok := rec.Attr("g")
	if !ok {
		t.Fatal("Attr(\"g\") group not found")
	}

	if val.Kind() != slog.KindGroup {
		t.Fatalf("expected g to be a group, got %v", val.Kind())
	}

	got := map[string]int64{}
	for _, a := range val.Group() {
		got[a.Key] = a.Value.Int64()
	}

	if len(got) != 2 || got["a"] != 1 || got["b"] != 2 {
		t.Errorf("group g = %v, want a=1 b=2 in one merged group", got)
	}
}

func TestRecorderResolvesLogValuer(t *testing.T) {
	logger, rec := NewRecorder()

	logger.Info("m", slog.Any("q", logValuerFunc(func() slog.Value {
		return slog.StringValue("resolved")
	})))

	val, ok := rec.Attr("q")
	if !ok {
		t.Fatal("Attr(\"q\") not found")
	}

	if val.Kind() != slog.KindString || val.String() != "resolved" {
		t.Errorf("q = %v (kind %v), want resolved string", val.String(), val.Kind())
	}
}

func TestRecorderBaseAttrsPrecedeRecordAttrs(t *testing.T) {
	logger, rec := NewRecorder()

	// WithAttrs ("base") must come before the per-call attr, like real handlers.
	logger.With(slog.String("k", "base")).Info("m", slog.String("k", "call"))

	rec.store.mu.Lock()
	defer rec.store.mu.Unlock()

	var order []string

	rec.store.records[0].Attrs(func(a slog.Attr) bool {
		if a.Key == "k" {
			order = append(order, a.Value.String())
		}

		return true
	})

	if len(order) != 2 || order[0] != "base" || order[1] != "call" {
		t.Errorf("attr order = %v, want [base call]", order)
	}
}

func TestCaptureGlobalRestores(t *testing.T) {
	before := Log()

	rec, restore := CaptureGlobal()
	Log().InfoContext(context.Background(), "captured")
	if rec.LastMessage() != "captured" {
		t.Errorf("expected captured message, got %q", rec.LastMessage())
	}

	restore()
	if Log() != before {
		t.Error("CaptureGlobal restore did not reinstate the previous logger")
	}
}

func TestCaptureGlobalContextAttrs(t *testing.T) {
	rec, restore := CaptureGlobal()
	defer restore()

	ctx := context.Background()
	ctx, _ = CtxWithFields(ctx, slog.String("req_id", "r1"))
	Log().InfoContext(ctx, "with-ctx")

	val, ok := rec.Attr("req_id")
	if !ok {
		t.Fatal("Attr(\"req_id\") not found")
	}

	if got := val.String(); got != "r1" {
		t.Errorf("Attr(\"req_id\") = %q, want %q", got, "r1")
	}
}
