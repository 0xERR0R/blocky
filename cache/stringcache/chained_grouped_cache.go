package stringcache

import (
	"sort"

	"golang.org/x/exp/maps"
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

func (c *ChainedGroupedCache) Contains(searchString string, groups []string) []string {
	groupMatchedMap := make(map[string]struct{}, len(groups))

	for _, cache := range c.caches {
		for _, group := range cache.Contains(searchString, groups) {
			groupMatchedMap[group] = struct{}{}
		}
	}

	matchedGroups := maps.Keys(groupMatchedMap)

	sort.Strings(matchedGroups)

	return matchedGroups
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
