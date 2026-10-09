package stringcache

import (
	"bufio"
	"os"
	"runtime"
	"strings"
	"testing"
)

// BLOCKY_WILDCARD_LIST selects a downloaded list without network access during
// the benchmark. Run the same benchmark on both revisions for comparable data.
func BenchmarkLargeList(b *testing.B) {
	path := os.Getenv("BLOCKY_WILDCARD_LIST")
	if path == "" {
		b.Skip("set BLOCKY_WILDCARD_LIST to a local wildcard list")
	}

	for _, kind := range []string{"exact", "wildcard"} {
		b.Run(kind, func(b *testing.B) {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			cache := loadBenchmarkWildcardList(b, path, kind)
			runtime.GC()
			runtime.ReadMemStats(&after)
			heap := float64(after.HeapAlloc) - float64(before.HeapAlloc)

			var sample []string
			i := 0
			forBenchmarkWildcard(b, path, func(entry string) {
				if i%997 == 0 {
					sample = append(sample, normalizeWildcard(entry))
				}
				i++
			})
			if len(sample) == 0 {
				b.Fatal("list contains no wildcard entries")
			}

			for _, queryKind := range []string{"base", "subdomain", "miss-tld", "miss-parent"} {
				if kind == "exact" && queryKind == "subdomain" {
					continue
				}
				b.Run(queryKind, func(b *testing.B) {
					queries := wildcardBenchmarkQueries(b, cache, sample, queryKind)
					b.ReportAllocs()
					i := 0
					for b.Loop() {
						cache.findMatch(queries[i])
						i++
						if i == len(queries) {
							i = 0
						}
					}
					b.ReportMetric(heap, "heap-B")
				})
			}
			runtime.KeepAlive(cache)
		})
	}
}

func wildcardBenchmarkQueries(b *testing.B, cache stringCache, sample []string, kind string) []string {
	b.Helper()
	wantHit := kind == "base" || kind == "subdomain"
	queries := make([]string, 0, len(sample))
	for _, base := range sample {
		var query string
		switch kind {
		case "base":
			query = base
		case "subdomain":
			query = "sub." + base
		case "miss-tld":
			query = base + ".invalid"
		case "miss-parent":
			query = "not-" + base
		}
		if _, hit := cache.findMatch(query); hit != wantHit {
			if wantHit {
				b.Fatalf("no match for %s query %q", kind, query)
			}

			continue // a broader rule in the list covers this miss candidate
		}
		queries = append(queries, query)
	}
	if len(queries) == 0 {
		b.Skipf("no %s queries: all candidates match stored rules", kind)
	}

	return queries
}

func loadBenchmarkWildcardList(b *testing.B, path, kind string) stringCache {
	b.Helper()
	factory := newWildcardCacheFactory()
	if kind == "exact" {
		factory = newStringCacheFactory()
	}
	forBenchmarkWildcard(b, path, func(entry string) {
		if kind == "exact" {
			entry = normalizeWildcard(entry)
		}
		factory.addEntry(entry)
	})

	return factory.create()
}

func forBenchmarkWildcard(b *testing.B, path string, visit func(string)) {
	b.Helper()
	file, err := os.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entry := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(entry, "*.") {
			visit(entry)
		}
	}
	if err := scanner.Err(); err != nil {
		b.Fatal(err)
	}
}
