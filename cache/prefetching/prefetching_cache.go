package prefetching

import (
	"context"
	"sync/atomic"
	"time"

	expirationcache "github.com/0xERR0R/expiration-cache"

	"github.com/0xERR0R/blocky/cache"
)

type PrefetchingExpiringLRUCache[T any] struct {
	cache                   cache.ExpiringCache[cacheValue[T]]
	prefetchingNameCache    cache.ExpiringCache[atomic.Uint32]
	reloadFn                ReloadEntryFn[T]
	prefetchThreshold       int
	prefetchExpires         time.Duration
	onPrefetchEntryReloaded OnEntryReloadedCallback
	onPrefetchCacheHit      expirationcache.OnCacheHitCallback

	// reloadPublisher, when set, is called with each entry reloaded by prefetching so
	// a decorator (e.g. Redis write-through) can propagate the refreshed entry. It is
	// stored atomically because it is wired during setup while the cleanup goroutine
	// (which reads it) is already running.
	reloadPublisher atomic.Pointer[func(key string, val *T, ttl time.Duration)]
}

type cacheValue[T any] struct {
	element  *T
	prefetch bool
}

// OnEntryReloadedCallback will be called if a prefetched entry is reloaded
type OnEntryReloadedCallback func(key string)

// ReloadEntryFn reloads a prefetched entry by key
type ReloadEntryFn[T any] func(ctx context.Context, key string) (*T, time.Duration)

type PrefetchingOptions[T any] struct {
	expirationcache.Options

	ReloadFn                ReloadEntryFn[T]
	PrefetchThreshold       int
	PrefetchExpires         time.Duration
	PrefetchMaxItemsCount   int
	OnPrefetchAfterPut      expirationcache.OnAfterPutCallback
	OnPrefetchEntryReloaded OnEntryReloadedCallback
	OnPrefetchCacheHit      expirationcache.OnCacheHitCallback
}

type PrefetchingCacheOption[T any] func(c *PrefetchingExpiringLRUCache[cacheValue[T]])

func NewPrefetchingCache[T any](ctx context.Context, options PrefetchingOptions[T]) *PrefetchingExpiringLRUCache[T] {
	pc := &PrefetchingExpiringLRUCache[T]{
		prefetchingNameCache: expirationcache.NewCache[atomic.Uint32](ctx, expirationcache.Options{
			CleanupInterval: time.Minute,
			MaxSize:         uint(options.PrefetchMaxItemsCount),
			OnAfterPutFn:    options.OnPrefetchAfterPut,
		}),
		prefetchExpires:         options.PrefetchExpires,
		prefetchThreshold:       options.PrefetchThreshold,
		reloadFn:                options.ReloadFn,
		onPrefetchEntryReloaded: options.OnPrefetchEntryReloaded,
		onPrefetchCacheHit:      options.OnPrefetchCacheHit,
	}

	pc.cache = expirationcache.NewCacheWithOnExpired[cacheValue[T]](ctx, options.Options, pc.onExpired)

	return pc
}

// Assert the prefetching cache satisfies the decorator's reload-publish hook so a
// signature drift fails to compile instead of silently disabling Redis sync.
var _ cache.ReloadPublishable[any] = (*PrefetchingExpiringLRUCache[any])(nil)

// SetReloadPublisher registers a function invoked with each entry reloaded by
// prefetching. A cache decorator uses it to propagate reloaded entries (which are
// stored directly by the inner expiration cache and so bypass the decorator).
func (e *PrefetchingExpiringLRUCache[T]) SetReloadPublisher(fn func(key string, val *T, ttl time.Duration)) {
	e.reloadPublisher.Store(&fn)
}

// check if a cache entry should be prefetched: was queried > threshold in the time window
func (e *PrefetchingExpiringLRUCache[T]) shouldPrefetch(cacheKey string) bool {
	if e.prefetchThreshold == 0 {
		return true
	}

	cnt, _ := e.prefetchingNameCache.Get(cacheKey)

	return cnt != nil && int64(cnt.Load()) > int64(e.prefetchThreshold)
}

func (e *PrefetchingExpiringLRUCache[T]) onExpired(
	ctx context.Context, cacheKey string,
) (val *cacheValue[T], ttl time.Duration) {
	if !e.shouldPrefetch(cacheKey) {
		return nil, 0
	}

	loadedVal, ttl := e.reloadFn(ctx, cacheKey)
	if loadedVal == nil {
		return nil, 0
	}

	if e.onPrefetchEntryReloaded != nil {
		e.onPrefetchEntryReloaded(cacheKey)
	}

	// skip the publish for non-positive TTLs: the decorator would drop them anyway.
	if p := e.reloadPublisher.Load(); p != nil && ttl > 0 {
		(*p)(cacheKey, loadedVal, ttl)
	}

	return &cacheValue[T]{loadedVal, true}, ttl
}

func (e *PrefetchingExpiringLRUCache[T]) trackCacheKeyQueryCount(cacheKey string) {
	var x *atomic.Uint32
	if x, _ = e.prefetchingNameCache.Get(cacheKey); x == nil {
		x = &atomic.Uint32{}
	}

	x.Add(1)
	e.prefetchingNameCache.Put(cacheKey, x, e.prefetchExpires)
}

func (e *PrefetchingExpiringLRUCache[T]) Put(key string, val *T, expiration time.Duration) {
	e.cache.Put(key, &cacheValue[T]{element: val, prefetch: false}, expiration)
}

// Get returns the value of cached entry with remained TTL. If entry is not cached, returns nil
func (e *PrefetchingExpiringLRUCache[T]) Get(key string) (val *T, expiration time.Duration) {
	e.trackCacheKeyQueryCount(key)

	res, exp := e.cache.Get(key)

	if res == nil {
		return nil, exp
	}

	if e.onPrefetchCacheHit != nil && res.prefetch {
		// Hit from prefetch cache
		e.onPrefetchCacheHit(key)
	}

	return res.element, exp
}

// TotalCount returns the total count of valid (not expired) elements
func (e *PrefetchingExpiringLRUCache[T]) TotalCount() int {
	return e.cache.TotalCount()
}

// Clear removes all cache entries
func (e *PrefetchingExpiringLRUCache[T]) Clear() {
	e.cache.Clear()
	e.prefetchingNameCache.Clear()
}
