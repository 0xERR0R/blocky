package stringcache

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
	// If a group matches in more than one chained cache (e.g. an exact entry and
	// a wildcard), we keep a single rule per group: the last chained cache wins.
	// One representative rule per group is enough for the block reason, and the
	// chain order is fixed, so the choice is stable across requests.
	var result map[string]string

	for _, cache := range c.caches {
		for group, rule := range cache.Contains(searchString, groups) {
			if result == nil {
				result = make(map[string]string, len(groups))
			}

			result[group] = rule
		}
	}

	return result
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
