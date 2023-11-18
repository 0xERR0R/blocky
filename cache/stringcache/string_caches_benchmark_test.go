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
// Most memory efficient: Wildcard (blocky/trie    radix) because of peak
// Fastest:               Wildcard (blocky/trie original)
//
//nolint:lll
// BenchmarkRegexFactory-8                1     1 253 023 507 ns/op   430.60 fact_heap_MB   430.60 peak_heap_MB   1 792 669 024 B/op   9 826 986 allocs/op
// BenchmarkStringFactory-8               7       163 969 933 ns/op    11.79 fact_heap_MB    26.91 peak_heap_MB      67 613 890 B/op       1 306 allocs/op
// BenchmarkWildcardFactory-8            19        60 592 988 ns/op    16.60 fact_heap_MB    16.60 peak_heap_MB      26 740 317 B/op      92 245 allocs/op (original)
// BenchmarkWildcardFactory-8            16        65 179 284 ns/op    14.92 fact_heap_MB    14.92 peak_heap_MB      27 997 734 B/op      52 937 allocs/op (radix)

func BenchmarkRegexFactory(b *testing.B) {
	benchmarkRegexFactory(b, newRegexCacheFactory)
}

func BenchmarkStringFactory(b *testing.B) {
	benchmarkStringFactory(b, newStringCacheFactory)
}

func BenchmarkWildcardFactory(b *testing.B) {
	benchmarkWildcardFactory(b, newWildcardCacheFactory)
}

func benchmarkRegexFactory(b *testing.B, newFactory func() cacheFactory) {
	benchmarkFactory(b, regexTestData, newFactory)
}

func benchmarkStringFactory(b *testing.B, newFactory func() cacheFactory) {
	benchmarkFactory(b, stringTestData, newFactory)
}

func benchmarkWildcardFactory(b *testing.B, newFactory func() cacheFactory) {
	benchmarkFactory(b, wildcardTestData, newFactory)
}

func benchmarkFactory(b *testing.B, data []string, newFactory func() cacheFactory) {
	baseMemStats = readMemStats()

	b.ReportAllocs()
	b.ResetTimer()

	var (
		factory cacheFactory
		cache   stringCache
	)

	for i := 0; i < b.N; i++ {
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
// Most memory efficient: Wildcard (blocky/trie radix)
// Fastest:               Wildcard (blocky/trie original)
//
//nolint:lll
// BenchmarkStringCache-8                 6       204 754 798 ns/op    15.11 cache_heap_MB              0 B/op          0 allocs/op
// BenchmarkWildcardCache-8              14        76 186 334 ns/op    16.61 cache_heap_MB              0 B/op          0 allocs/op (original)
// BenchmarkWildcardCache-8              12        95 316 121 ns/op    14.91 cache_heap_MB              0 B/op          0 allocs/op (radix)

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
	benchmarkCache(b, stringTestData, newFactory)
}

func benchmarkWildcardCache(b *testing.B, newFactory func() cacheFactory) {
	benchmarkCache(b, wildcardTestData, newFactory)
}

func benchmarkCache(b *testing.B, data []string, newFactory func() cacheFactory) {
	baseMemStats = readMemStats()

	factory := newFactory()

	for _, s := range data {
		factory.addEntry(s)
	}

	cache := factory.create()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Always use the plain strings for search:
		// - wildcards and regexes need a plain string query
		// - all benchmarks will do the same number of queries
		for _, s := range stringTestData {
			if !cache.contains(s) {
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
