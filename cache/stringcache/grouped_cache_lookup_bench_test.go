package stringcache

import (
	"fmt"
	"testing"
)

// buildBlockingCache builds a chained grouped cache mirroring the composition that
// lists.ListCache uses (regex, then wildcard, then string — the catch-all string
// cache must be last so chainedGroupFactory.AddEntry routes entries correctly).
// Each group is populated with nRegex regexes, nWild wildcards and nString exact
// entries so the per-lookup cost of the locking (Tier 2a) and the chain ordering
// /short-circuit (Tier 2b) is visible.
func buildBlockingCache(tb testing.TB, groups []string, nRegex, nWild, nString int) *ChainedGroupedCache {
	tb.Helper()

	c := NewChainedGroupedCache(
		NewInMemoryGroupedRegexCache(),
		NewInMemoryGroupedWildcardCache(),
		NewInMemoryGroupedStringCache(),
	)

	for _, g := range groups {
		f := c.Refresh(g)

		for i := range nRegex {
			f.AddEntry(fmt.Sprintf(`/^regex%d\..*$/`, i))
		}

		for i := range nWild {
			f.AddEntry(fmt.Sprintf("*.wild%d.example", i))
		}

		for i := range nString {
			f.AddEntry(fmt.Sprintf("string%d.example.com", i))
		}

		f.Finish()
	}

	return c
}

// BenchmarkGroupedCacheStringHit measures looking up a domain that is an exact
// entry in the (cheapest, last-in-chain) string cache while the group also holds
// regexes. This is the case Tier 2b targets: today the lookup pays a full linear
// regex scan before reaching the string match.
func BenchmarkGroupedCacheStringHit(b *testing.B) {
	cache := buildBlockingCache(b, []string{"default"}, 200, 200, 5000)
	groups := []string{"default"}
	hit := "string1234.example.com"

	b.ReportAllocs()

	for b.Loop() {
		if m := cache.Contains(hit, groups); len(m) == 0 {
			b.Fatalf("expected %q to match", hit)
		}
	}
}

// BenchmarkGroupedCacheMiss measures a domain present in none of the sub-caches.
// A miss must consult every sub-cache regardless of ordering, so this is the
// floor that short-circuiting cannot improve — kept to confirm it does not
// regress.
func BenchmarkGroupedCacheMiss(b *testing.B) {
	cache := buildBlockingCache(b, []string{"default"}, 200, 200, 5000)
	groups := []string{"default"}
	miss := "not-present.example.org"

	b.ReportAllocs()

	for b.Loop() {
		if m := cache.Contains(miss, groups); len(m) != 0 {
			b.Fatalf("expected %q to miss", miss)
		}
	}
}

// BenchmarkGroupedCacheLockContention isolates the per-group locking cost (Tier 2a):
// tiny caches make the actual matching work negligible, many groups multiply the
// number of lock acquisitions per lookup, and RunParallel hammers the shared
// reader-count cache line that an RWMutex maintains but a lock-free atomic load
// does not.
func BenchmarkGroupedCacheLockContention(b *testing.B) {
	groups := make([]string, 16)
	for i := range groups {
		groups[i] = fmt.Sprintf("group%d", i)
	}

	cache := buildBlockingCache(b, groups, 0, 0, 1)
	hit := "string0.example.com"

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if m := cache.Contains(hit, groups); len(m) != len(groups) {
				b.Fatalf("expected %q to match all groups, got %d", hit, len(m))
			}
		}
	})
}

// BenchmarkGroupedCacheParallel measures concurrent lookups across several groups.
// It surfaces the Tier 2a cost: the per-group RWMutex RLock/RUnlock contends the
// reader-count cache line across in-flight requests, where a lock-free atomic load
// would not.
func BenchmarkGroupedCacheParallel(b *testing.B) {
	groups := []string{"default", "kids", "guests", "iot"}
	cache := buildBlockingCache(b, groups, 50, 200, 5000)
	hit := "string1234.example.com"

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if m := cache.Contains(hit, groups); len(m) != len(groups) {
				b.Fatalf("expected %q to match all groups, got %d", hit, len(m))
			}
		}
	})
}
