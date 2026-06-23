package log

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestConfigureJSONEmitsKeys(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Level: Level(slog.LevelInfo), Format: FormatTypeJson, Timestamp: true}
	configureTo(&buf, cfg) // test seam (Step 3)

	ctx := ctxWithAttrs(context.Background(), slog.String("req_id", "xyz"))
	Log().InfoContext(ctx, "msg", slog.String("prefix", "blocking"))

	out := buf.String()
	for _, want := range []string{`"req_id":"xyz"`, `"prefix":"blocking"`, `"msg":"msg"`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON output missing %s; got: %s", want, out)
		}
	}
}

func TestConfigureTimestampDisabled(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Level: Level(slog.LevelInfo), Format: FormatTypeJson, Timestamp: false}
	configureTo(&buf, cfg)

	Log().Info("msg")

	if strings.Contains(buf.String(), `"time"`) {
		t.Errorf("expected no time key when Timestamp=false; got: %s", buf.String())
	}
}

func TestSetLevelDynamic(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Level: Level(slog.LevelInfo), Format: FormatTypeJson, Timestamp: true}
	configureTo(&buf, cfg)

	Log().Debug("hidden") // below info
	if strings.Contains(buf.String(), "hidden") {
		t.Fatal("debug should be hidden at info level")
	}

	SetLevel(slog.LevelDebug)
	Log().Debug("nowvisible")
	if !strings.Contains(buf.String(), "nowvisible") {
		t.Error("debug should be visible after SetLevel(Debug)")
	}
}
