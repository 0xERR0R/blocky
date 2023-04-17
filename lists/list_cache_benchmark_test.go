package lists

import (
	"testing"

	"github.com/0xERR0R/blocky/config"
)

func BenchmarkRefresh(b *testing.B) {
	file1, _ := createTestListFile(b.TempDir(), 100000)
	file2, _ := createTestListFile(b.TempDir(), 150000)
	file3, _ := createTestListFile(b.TempDir(), 130000)
	lists := map[string][]config.BytesSource{
		"gr1": config.NewBytesSources(file1, file2, file3),
	}

	cfg := config.SourceLoadingConfig{
		Concurrency:   5,
		RefreshPeriod: config.Duration(-1),
	}
	downloader := NewDownloader(config.DownloaderConfig{}, nil)
	cache, _ := NewListCache(ListCacheTypeBlacklist, cfg, lists, downloader)

	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		cache.Refresh()
	}
}
