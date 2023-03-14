package stringcache

type stringCacheFactoryFn func() CacheFactory

type InMemoryGroupedCache struct {
	caches    map[string]StringCache
	factoryFn stringCacheFactoryFn
}

func NewInMemoryGroupedStringCache() *InMemoryGroupedCache {
	return &InMemoryGroupedCache{
		caches:    make(map[string]StringCache),
		factoryFn: newStringCacheFactory,
	}
}

func NewInMemoryGroupedRegexCache() *InMemoryGroupedCache {
	return &InMemoryGroupedCache{
		caches:    make(map[string]StringCache),
		factoryFn: newRegexCacheFactory,
	}
}

func (c *InMemoryGroupedCache) ElementCount(group string) int {
	cache, found := c.caches[group]
	if !found {
		return 0
	}

	return cache.ElementCount()
}

func (c *InMemoryGroupedCache) Contains(searchString string, groups []string) []string {
	var result []string

	for _, group := range groups {
		cache, found := c.caches[group]

		if found && cache.Contains(searchString) {
			result = append(result, group)
		}
	}

	return result
}

func (c *InMemoryGroupedCache) Refresh(group string) GroupFactory {
	return &inMemoryGroupFactory{
		factory: c.factoryFn(),
		callbackFn: func(sc StringCache) {
			c.caches[group] = sc
		},
	}
}

type inMemoryGroupFactory struct {
	factory    CacheFactory
	callbackFn func(StringCache)
}

func (c *inMemoryGroupFactory) AddEntry(entry string) {
	c.factory.AddEntry(entry)
}

func (c *inMemoryGroupFactory) Count() int {
	return c.factory.Count()
}

func (c *inMemoryGroupFactory) Finish() {
	sc := c.factory.Create()
	c.callbackFn(sc)
}
