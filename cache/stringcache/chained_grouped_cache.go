package stringcache

import (
	"maps"
	"slices"
)

type ChainedGroupedCache struct {
	caches []GroupedStringCache
}

func NewChainedGroupedCache(caches ...GroupedStringCache) *ChainedGroupedCache {
	return &ChainedGroupedCache{
		caches: caches,
	}
}

func (c *ChainedGroupedCache) ElementCount(group string) int {
	sum := 0
	for _, cache := range c.caches {
		sum += cache.ElementCount(group)
	}

	return sum
}

func (c *ChainedGroupedCache) Contains(searchString string, groups []string) map[string]string {
	// result is allocated lazily so the common no-match case stays allocation-free.
	// Ordering of matched groups is not defined here; callers that render the
	// result sort it (see resolver.formatBlockReason).
	//
	// Sub-caches are queried cheapest-first, i.e. in reverse of construction order.
	// The chain is built most-expensive-first (regex, wildcard, string) because
	// chainedGroupFactory routes each insert to the first accepting cache and the
	// string cache is the catch-all, so it must be last. Querying in reverse means
	// an exact string-denylist hit never pays the linear regex scan first.
	//
	// Once a group matches, it is dropped from the set still being searched, so no
	// group is looked up in more than one sub-cache. If a group matches in more
	// than one chained cache (e.g. an exact entry and a wildcard), a single rule is
	// reported: the one from the last (cheapest) cache in construction order. That
	// is the same representative the previous "last chained cache wins" produced —
	// reverse-first-match equals forward-last-match under short-circuiting.
	var result map[string]string

	remaining := groups

	for _, cache := range slices.Backward(c.caches) {
		matches := cache.Contains(searchString, remaining)
		if len(matches) == 0 {
			continue
		}

		if result == nil {
			// Adopt the sub-cache's map instead of allocating a second one; the common
			// single-sub-cache match then costs one map, not two. We then retain and
			// mutate it (via maps.Copy below), which is only safe because the
			// GroupedStringCache contract requires Contains to return a fresh, caller-
			// ownable map per call (never a retained/shared/pooled one).
			result = matches
		} else {
			maps.Copy(result, matches)
		}

		if len(result) == len(groups) {
			break // every group matched; nothing left to search
		}

		remaining = remainingGroups(groups, result)
	}

	return result
}

// remainingGroups returns the groups that do not yet have a match in matched. It is
// only reached when a lookup matches some but not all groups across different
// sub-caches; the hot single-group path matches (and breaks) or misses without
// allocating here.
func remainingGroups(groups []string, matched map[string]string) []string {
	out := make([]string, 0, len(groups)-len(matched))

	for _, g := range groups {
		if _, done := matched[g]; !done {
			out = append(out, g)
		}
	}

	return out
}

func (c *ChainedGroupedCache) Refresh(group string) GroupFactory {
	cacheFactories := make([]GroupFactory, len(c.caches))
	for i, cache := range c.caches {
		cacheFactories[i] = cache.Refresh(group)
	}

	return &chainedGroupFactory{
		cacheFactories: cacheFactories,
	}
}

type chainedGroupFactory struct {
	cacheFactories []GroupFactory
}

func (c *chainedGroupFactory) AddEntry(entry string) bool {
	for _, factory := range c.cacheFactories {
		if factory.AddEntry(entry) {
			return true
		}
	}

	return false
}

func (c *chainedGroupFactory) Count() int {
	var cnt int
	for _, factory := range c.cacheFactories {
		cnt += factory.Count()
	}

	return cnt
}

func (c *chainedGroupFactory) Finish() {
	for _, factory := range c.cacheFactories {
		factory.Finish()
	}
}
