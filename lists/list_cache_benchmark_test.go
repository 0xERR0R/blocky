package lists

import (
	"context"
	"testing"

	"github.com/0xERR0R/blocky/config"
)

func BenchmarkRefresh(b *testing.B) {
	file1, _ := createTestListFile(b, b.TempDir(), 100000)
	file2, _ := createTestListFile(b, b.TempDir(), 150000)
	file3, _ := createTestListFile(b, b.TempDir(), 130000)
	lists := map[string][]config.BytesSource{
		"gr1": config.NewBytesSources(file1, file2, file3),
	}

	cfg := config.SourceLoading{
		Concurrency:   5,
		RefreshPeriod: config.Duration(-1),
	}
	downloader := NewDownloader(config.Downloader{}, nil)
	cache, err := NewListCache(context.Background(), ListCacheTypeDenylist, cfg, lists, downloader)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if err := cache.Refresh(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
