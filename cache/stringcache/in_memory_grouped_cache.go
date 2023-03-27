package stringcache

import "sync"

type stringCacheFactoryFn func() cacheFactory

type InMemoryGroupedCache struct {
	caches    map[string]stringCache
	lock      sync.RWMutex
	factoryFn stringCacheFactoryFn
}

func NewInMemoryGroupedStringCache() *InMemoryGroupedCache {
	return &InMemoryGroupedCache{
		caches:    make(map[string]stringCache),
		factoryFn: newStringCacheFactory,
	}
}

func NewInMemoryGroupedRegexCache() *InMemoryGroupedCache {
	return &InMemoryGroupedCache{
		caches:    make(map[string]stringCache),
		factoryFn: newRegexCacheFactory,
	}
}

func (c *InMemoryGroupedCache) ElementCount(group string) int {
	c.lock.RLock()
	cache, found := c.caches[group]
	c.lock.RUnlock()

	if !found {
		return 0
	}

	return cache.elementCount()
}

func (c *InMemoryGroupedCache) Contains(searchString string, groups []string) []string {
	var result []string

	for _, group := range groups {
		c.lock.RLock()
		cache, found := c.caches[group]
		c.lock.RUnlock()

		if found && cache.contains(searchString) {
			result = append(result, group)
		}
	}

	return result
}

func (c *InMemoryGroupedCache) Refresh(group string) GroupFactory {
	return &inMemoryGroupFactory{
		factory: c.factoryFn(),
		finishFn: func(sc stringCache) {
			c.lock.Lock()
			c.caches[group] = sc
			c.lock.Unlock()
		},
	}
}

type inMemoryGroupFactory struct {
	factory  cacheFactory
	finishFn func(stringCache)
}

func (c *inMemoryGroupFactory) AddEntry(entry string) {
	c.factory.addEntry(entry)
}

func (c *inMemoryGroupFactory) Count() int {
	return c.factory.count()
}

func (c *inMemoryGroupFactory) Finish() {
	sc := c.factory.create()
	c.finishFn(sc)
}
