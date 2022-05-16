package lists

import (
	"testing"
)

func BenchmarkRefresh(b *testing.B) {
	file1 := createTestListFile(b.TempDir(), 100000)
	file2 := createTestListFile(b.TempDir(), 150000)
	file3 := createTestListFile(b.TempDir(), 130000)
	lists := map[string][]string{
		"gr1": {file1, file2, file3},
	}

	cache, _ := NewListCache(ListCacheTypeBlacklist, lists, -1, NewDownloader(), 5)

	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		cache.Refresh()
	}
}
