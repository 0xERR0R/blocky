package stringcache

import (
	"maps"
	"sync"
	"sync/atomic"
)

type stringCacheFactoryFn func() cacheFactory

// InMemoryGroupedCache holds one stringCache per group. The group map only changes
// on list refresh, while it is read on every query, so it is kept behind an
// atomic.Pointer and replaced copy-on-write: lookups are a single lock-free atomic
// load with no per-group locking, and refreshes (serialised by writeLock) swap in a
// fresh map. This avoids the reader-count cache-line contention an RWMutex would
// incur across in-flight requests.
type InMemoryGroupedCache struct {
	caches    atomic.Pointer[map[string]stringCache]
	writeLock sync.Mutex
	factoryFn stringCacheFactoryFn
}

func newInMemoryGroupedCache(factoryFn stringCacheFactoryFn) *InMemoryGroupedCache {
	c := &InMemoryGroupedCache{factoryFn: factoryFn}

	empty := make(map[string]stringCache)
	c.caches.Store(&empty)

	return c
}

func NewInMemoryGroupedStringCache() *InMemoryGroupedCache {
	return newInMemoryGroupedCache(newStringCacheFactory)
}

func NewInMemoryGroupedRegexCache() *InMemoryGroupedCache {
	return newInMemoryGroupedCache(newRegexCacheFactory)
}

func NewInMemoryGroupedWildcardCache() *InMemoryGroupedCache {
	return newInMemoryGroupedCache(newWildcardCacheFactory)
}

func (c *InMemoryGroupedCache) ElementCount(group string) int {
	cache, found := (*c.caches.Load())[group]
	if !found {
		return 0
	}

	return cache.elementCount()
}

func (c *InMemoryGroupedCache) Contains(searchString string, groups []string) map[string]string {
	// result is allocated lazily so the common no-match case stays allocation-free.
	var result map[string]string

	// Single lock-free load: the snapshot is immutable, so it is safe to read for
	// the whole lookup even if a concurrent refresh swaps in a new map.
	caches := *c.caches.Load()

	for _, group := range groups {
		if cache, found := caches[group]; found {
			if rule, ok := cache.findMatch(searchString); ok {
				if result == nil {
					result = make(map[string]string, len(groups))
				}

				result[group] = rule
			}
		}
	}

	return result
}

func (c *InMemoryGroupedCache) Refresh(group string) GroupFactory {
	return &inMemoryGroupFactory{
		factory:  c.factoryFn(),
		finishFn: func(sc stringCache) { c.storeGroup(group, sc) },
	}
}

// storeGroup copy-on-write replaces a single group's cache (or removes it when sc is
// nil). Writers are serialised by writeLock so concurrent group refreshes cannot
// lose each other's updates; readers never block, they just observe the previous or
// the new snapshot.
func (c *InMemoryGroupedCache) storeGroup(group string, sc stringCache) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	old := *c.caches.Load()

	updated := make(map[string]stringCache, len(old)+1)
	maps.Copy(updated, old)

	if sc != nil {
		updated[group] = sc
	} else {
		delete(updated, group)
	}

	c.caches.Store(&updated)
}

type inMemoryGroupFactory struct {
	factory  cacheFactory
	finishFn func(stringCache)
}

func (c *inMemoryGroupFactory) AddEntry(entry string) bool {
	return c.factory.addEntry(entry)
}

func (c *inMemoryGroupFactory) Count() int {
	return c.factory.count()
}

func (c *inMemoryGroupFactory) Finish() {
	sc := c.factory.create()
	c.finishFn(sc)
}
