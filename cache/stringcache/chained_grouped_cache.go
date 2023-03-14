package stringcache

import "sort"

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

func (c *ChainedGroupedCache) Contains(searchString string, groups []string) []string {
	result := make(map[string]bool)

	for _, cache := range c.caches {
		for _, group := range cache.Contains(searchString, groups) {
			result[group] = true
		}
	}

	keys := make([]string, len(result))

	i := 0

	for k := range result {
		keys[i] = k
		i++
	}

	sort.Strings(keys)

	return keys
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

func (c *chainedGroupFactory) AddEntry(entry string) {
	for _, factory := range c.cacheFactories {
		factory.AddEntry(entry)
	}
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
