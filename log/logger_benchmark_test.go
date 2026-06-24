package log

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func benchSetup(b *testing.B, level slog.Level) {
	b.Helper()
	configureTo(io.Discard, &Config{Level: Level(level), Format: FormatTypeText, Timestamp: true})
	b.ReportAllocs()
}

func requestAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("req_id", "b8f4c1e2-0000-1111-2222-333344445555"),
		slog.String("question", "A example.com."),
		slog.String("client_ip", "192.168.178.1"),
	}
}

func BenchmarkCtxWithFields(b *testing.B) {
	benchSetup(b, slog.LevelInfo)
	ctx := context.Background()

	for b.Loop() {
		_, _ = CtxWithFields(ctx, requestAttrs()...)
	}
}

func BenchmarkFromCtx(b *testing.B) {
	ctx, _ := CtxWithFields(context.Background(), requestAttrs()...)
	benchSetup(b, slog.LevelInfo)

	for b.Loop() {
		_ = FromCtx(ctx)
	}
}

func BenchmarkFromCtxWithPrefix(b *testing.B) {
	ctx, _ := CtxWithFields(context.Background(), requestAttrs()...)
	benchSetup(b, slog.LevelInfo)

	for b.Loop() {
		_ = FromCtx(ctx).With(slog.String(prefixKey, "blocking"))
	}
}

var chainPrefixes = []string{
	"client_names", "query_logging", "metrics", "blocking", "caching",
	"conditional", "custom_dns", "hosts_file", "dns64", "upstream",
}

func benchmarkRequestChain(b *testing.B, level slog.Level) {
	b.Helper()
	benchSetup(b, level)
	base := context.Background()

	for b.Loop() {
		ctx, _ := CtxWithFields(base, requestAttrs()...)
		for _, prefix := range chainPrefixes {
			logger := FromCtx(ctx).With(slog.String(prefixKey, prefix))
			logger.DebugContext(ctx, "resolving in "+prefix)
		}
	}
}

func BenchmarkRequestChain_InfoLevel(b *testing.B)  { benchmarkRequestChain(b, slog.LevelInfo) }
func BenchmarkRequestChain_DebugLevel(b *testing.B) { benchmarkRequestChain(b, slog.LevelDebug) }
