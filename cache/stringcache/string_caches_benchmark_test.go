package stringcache

import (
	"context"
	"fmt"
	"math"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/0xERR0R/blocky/lists/parsers"
	"github.com/0xERR0R/blocky/log"
)

var (
	// String and Wildcard benchmarks don't use the exact same data,
	// but since it's two versions of the same list it's closer to
	// the real world: we build the cache using different sources, but then check
	// the same list of domains.
	//
	// It is possible to run the benchmarks using the exact same data: set `useRealLists`
	// to `false`. The results should be similar to the current ones, with memory use
	// changing the most.
	useRealLists = true

	regexTestData    []string
	stringTestData   []string
	wildcardTestData []string

	baseMemStats runtime.MemStats
)

func init() {
	// If you update either list, make sure both are the list version (see file header).
	stringTestData = loadTestdata("../../helpertest/data/oisd-big-plain.txt")

	if useRealLists {
		wildcardTestData = loadTestdata("../../helpertest/data/oisd-big-wildcard.txt")

		// Domain is in plain but not wildcard list, add it so `benchmarkCache` doesn't fail
		wildcardTestData = append(wildcardTestData, "*.btest.oisd.nl")
	} else {
		wildcardTestData = make([]string, 0, len(stringTestData))

		for _, domain := range stringTestData {
			wildcardTestData = append(wildcardTestData, "*."+domain)
		}
	}

	// OISD regex list is the exact same as the wildcard one, just using a different format
	regexTestData = make([]string, 0, len(wildcardTestData))

	for _, wildcard := range wildcardTestData {
		domain := strings.TrimPrefix(wildcard, "*.")

		// /^(.*\.)?subdomain\.example\.com$/
		regex := fmt.Sprintf(`/^(.*\.)?%s$/`, regexp.QuoteMeta(domain))

		regexTestData = append(regexTestData, regex)
	}
}

// --- Cache Building ---
//
// Exact and wildcard entries are 64-bit hashes (see hash.go). Measured with
// benchstat (n=6) on linux/arm64, Go 1.27, with the oisd big lists, as
// "before (sorted text / trie) -> after (hashes)":
//
// BenchmarkStringFactory     73.4ms ->  70.1ms (~same)  63.7Mi ->  32.7Mi B/op  1257 ->  40 allocs  peak_heap_MB 26.9 -> 7.4
// BenchmarkWildcardFactory   49.6ms ->  29.5ms (-40%)   14.8Mi ->   8.2Mi B/op  25719 -> 34 allocs  peak_heap_MB 3.90 -> 1.93

func BenchmarkRegexFactory(b *testing.B) {
	benchmarkRegexFactory(b, newRegexCacheFactory)
}

func BenchmarkStringFactory(b *testing.B) {
	benchmarkStringFactory(b, newStringCacheFactory)
}

// BenchmarkStringFactoryScaling builds caches of increasing size where every
// entry has the same length, so they all land in a single length bucket. This
// is the worst case for the factory and makes its build complexity visible:
// a sorted insert that shifts the bucket on every entry is O(n^2), so ns/op
// roughly quadruples when n doubles; a build that sorts once is O(n log n), so
// ns/op roughly doubles when n doubles.
func BenchmarkStringFactoryScaling(b *testing.B) {
	for _, n := range []int{50_000, 100_000, 200_000} {
		data := sameLengthData(n)

		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				factory := newStringCacheFactory()

				for _, s := range data {
					factory.addEntry(s)
				}

				_ = factory.create()
			}
		})
	}
}

// sameLengthData returns n distinct entries that all share the same length,
// generated in reverse-sorted order to maximise the cost of an in-order insert.
func sameLengthData(n int) []string {
	data := make([]string, n)
	for i := range data {
		data[i] = fmt.Sprintf("%010d.example", n-i-1)
	}

	return data
}

func BenchmarkWildcardFactory(b *testing.B) {
	benchmarkWildcardFactory(b, newWildcardCacheFactory)
}

func benchmarkRegexFactory(b *testing.B, newFactory func() cacheFactory) {
	b.Helper()
	benchmarkFactory(b, regexTestData, newFactory)
}

func benchmarkStringFactory(b *testing.B, newFactory func() cacheFactory) {
	b.Helper()
	benchmarkFactory(b, stringTestData, newFactory)
}

func benchmarkWildcardFactory(b *testing.B, newFactory func() cacheFactory) {
	b.Helper()
	benchmarkFactory(b, wildcardTestData, newFactory)
}

func benchmarkFactory(b *testing.B, data []string, newFactory func() cacheFactory) {
	b.Helper()

	baseMemStats = readMemStats()

	b.ReportAllocs()
	b.ResetTimer()

	var (
		factory cacheFactory
		cache   stringCache
	)

	for b.Loop() {
		factory = newFactory()

		for _, s := range data {
			if !factory.addEntry(s) {
				b.Fatalf("cache didn't insert value: %s", s)
			}
		}

		cache = factory.create()
	}

	b.StopTimer()
	reportMemUsage(b, "peak", factory, cache)
	reportMemUsage(b, "fact", factory) // cache will be GC'd
}

// --- Cache Querying ---
//
// Exact and wildcard entries are 64-bit hashes (see hash.go). Measured with
// benchstat (n=6) on linux/arm64, Go 1.27, with the oisd big lists, as
// "before (sorted text / trie) -> after (hashes)":
//
// BenchmarkStringCache      111.0ms -> 79.4ms (-28%)  0 allocs both                   cache_heap_MB 15.11 -> 7.45
// BenchmarkWildcardCache    124.4ms -> 76.9ms (-38%)  681.7k allocs both (rule string per hit)  cache_heap_MB 3.87 -> 1.93
//
// Per lookup, see BenchmarkLargeList (oisd-big-wildcard.txt), in ns:
//   exact/base 135.9 -> 38.1   exact/miss-tld 128.0 -> 27.5   exact/miss-parent 82.4 -> 24.0
//   wildcard/base 179.9 -> 76.9   wildcard/subdomain 182.3 -> 109.8   wildcard/miss-parent 35.7 -> 32.0
//   wildcard/miss-tld 11.2 -> 38.7 (n=10): the trie's TLD map short-circuited unknown TLDs,
//   the walk now hashes the name and probes each label. Accepted.
// BenchmarkGroupedCacheStringHit 168 -> 152 ns (n=10); miss, parallel and lock contention are unchanged.

// Regex search is too slow to even complete
// func BenchmarkRegexCache(b *testing.B) {
// 	benchmarkRegexCache(b, newRegexCacheFactory)
// }

func BenchmarkStringCache(b *testing.B) {
	benchmarkStringCache(b, newStringCacheFactory)
}

func BenchmarkWildcardCache(b *testing.B) {
	benchmarkWildcardCache(b, newWildcardCacheFactory)
}

// func benchmarkRegexCache(b *testing.B, newFactory func() cacheFactory) {
// 	benchmarkCache(b, regexTestData, newFactory)
// }

func benchmarkStringCache(b *testing.B, newFactory func() cacheFactory) {
	b.Helper()
	benchmarkCache(b, stringTestData, newFactory)
}

func benchmarkWildcardCache(b *testing.B, newFactory func() cacheFactory) {
	b.Helper()
	benchmarkCache(b, wildcardTestData, newFactory)
}

func benchmarkCache(b *testing.B, data []string, newFactory func() cacheFactory) {
	b.Helper()

	baseMemStats = readMemStats()

	factory := newFactory()

	for _, s := range data {
		factory.addEntry(s)
	}

	cache := factory.create()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		// Always use the plain strings for search:
		// - wildcards and regexes need a plain string query
		// - all benchmarks will do the same number of queries
		for _, s := range stringTestData {
			if _, ok := cache.findMatch(s); !ok {
				b.Fatalf("cache is missing value from stringTestData: %s", s)
			}
		}
	}

	b.StopTimer()
	reportMemUsage(b, "cache", cache)
}

// ---

func readMemStats() (res runtime.MemStats) {
	runtime.GC()
	debug.FreeOSMemory()

	runtime.ReadMemStats(&res)

	return res
}

func reportMemUsage(b *testing.B, prefix string, toKeepAllocated ...any) {
	b.Helper()

	m := readMemStats()

	b.ReportMetric(toMB(m.HeapAlloc-baseMemStats.HeapAlloc), prefix+"_heap_MB")

	// Forces Go to keep the values allocated, meaning we include them in the above measurement
	// You can tell it works because factory benchmarks have different values for both calls
	for i := range toKeepAllocated {
		toKeepAllocated[i] = nil
	}
}

func toMB(b uint64) float64 {
	const bytesInKB = float64(1024)

	kb := float64(b) / bytesInKB

	return math.Round(kb) / 1024
}

func loadTestdata(path string) (res []string) {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	p := parsers.AllowErrors(parsers.Hosts(f), parsers.NoErrorLimit)
	p.OnErr(func(err error) {
		log.Log().Warnf("could not parse line in %s: %s", path, err)
	})

	err = parsers.ForEach[*parsers.HostsIterator](context.Background(), p, func(hosts *parsers.HostsIterator) error {
		return hosts.ForEach(func(host string) error {
			res = append(res, host)

			return nil
		})
	})
	if err != nil {
		panic(err)
	}

	return res
}
