package expirationcache

import (
	"context"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

const (
	defaultCleanUpInterval = 10 * time.Second
	defaultSize            = 10_000
)

type element[T any] struct {
	val            *T
	expiresEpochMs int64
}

type ExpiringLRUCache[T any] struct {
	cleanUpInterval time.Duration
	preExpirationFn OnExpirationCallback[T]
	onCacheHit      OnCacheHitCallback
	onCacheMiss     OnCacheMissCallback
	onAfterPut      OnAfterPutCallback
	lru             *lru.Cache
}

type Options struct {
	OnCacheHitFn    OnCacheHitCallback
	OnCacheMissFn   OnCacheMissCallback
	OnAfterPutFn    OnAfterPutCallback
	CleanupInterval time.Duration
	MaxSize         uint
}

// OnExpirationCallback will be called just before an element gets expired and will
// be removed from cache. This function can return new value and TTL to leave the
// element in the cache or nil to remove it
type OnExpirationCallback[T any] func(ctx context.Context, key string) (val *T, ttl time.Duration)

// OnCacheHitCallback will be called on cache get if entry was found
type OnCacheHitCallback func(key string)

// OnCacheMissCallback will be called on cache get and entry was not found
type OnCacheMissCallback func(key string)

// OnAfterPutCallback will be called after put, receives new element count as parameter
type OnAfterPutCallback func(newSize int)

func NewCache[T any](ctx context.Context, options Options) *ExpiringLRUCache[T] {
	return NewCacheWithOnExpired[T](ctx, options, nil)
}

func NewCacheWithOnExpired[T any](ctx context.Context, options Options,
	onExpirationFn OnExpirationCallback[T],
) *ExpiringLRUCache[T] {
	l, _ := lru.New(defaultSize)
	c := &ExpiringLRUCache[T]{
		cleanUpInterval: defaultCleanUpInterval,
		preExpirationFn: func(ctx context.Context, key string) (val *T, ttl time.Duration) {
			return nil, 0
		},
		onCacheHit:  func(key string) {},
		onCacheMiss: func(key string) {},
		lru:         l,
	}

	if options.CleanupInterval > 0 {
		c.cleanUpInterval = options.CleanupInterval
	}

	if options.MaxSize > 0 {
		l, _ := lru.New(int(options.MaxSize))
		c.lru = l
	}

	if options.OnAfterPutFn != nil {
		c.onAfterPut = options.OnAfterPutFn
	}

	if options.OnCacheHitFn != nil {
		c.onCacheHit = options.OnCacheHitFn
	}

	if options.OnCacheMissFn != nil {
		c.onCacheMiss = options.OnCacheMissFn
	}

	if onExpirationFn != nil {
		c.preExpirationFn = onExpirationFn
	}

	go periodicCleanup(ctx, c)

	return c
}

func periodicCleanup[T any](ctx context.Context, c *ExpiringLRUCache[T]) {
	ticker := time.NewTicker(c.cleanUpInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanUp()
		case <-ctx.Done():
			return
		}
	}
}

func (e *ExpiringLRUCache[T]) cleanUp() {
	var expiredKeys []string

	// check for expired items and collect expired keys
	for _, k := range e.lru.Keys() {
		if v, ok := e.lru.Peek(k); ok {
			if isExpired(v.(*element[T])) {
				expiredKeys = append(expiredKeys, k.(string))
			}
		}
	}

	if len(expiredKeys) > 0 {
		var keysToDelete []string

		for _, key := range expiredKeys {
			newVal, newTTL := e.preExpirationFn(context.Background(), key)
			if newVal != nil {
				e.Put(key, newVal, newTTL)
			} else {
				keysToDelete = append(keysToDelete, key)
			}
		}

		for _, key := range keysToDelete {
			e.lru.Remove(key)
		}
	}
}

func (e *ExpiringLRUCache[T]) Put(key string, val *T, ttl time.Duration) {
	if ttl <= 0 {
		// entry should be considered as already expired
		return
	}

	expiresEpochMs := time.Now().UnixMilli() + ttl.Milliseconds()

	// add new item
	e.lru.Add(key, &element[T]{
		val:            val,
		expiresEpochMs: expiresEpochMs,
	})

	if e.onAfterPut != nil {
		e.onAfterPut(e.lru.Len())
	}
}

func (e *ExpiringLRUCache[T]) Get(key string) (val *T, ttl time.Duration) {
	el, found := e.lru.Get(key)

	if found {
		e.onCacheHit(key)

		return el.(*element[T]).val, calculateRemainTTL(el.(*element[T]).expiresEpochMs)
	}

	e.onCacheMiss(key)

	return nil, 0
}

func isExpired[T any](el *element[T]) bool {
	return el.expiresEpochMs > 0 && time.Now().UnixMilli() > el.expiresEpochMs
}

func calculateRemainTTL(expiresEpoch int64) time.Duration {
	if now := time.Now().UnixMilli(); now < expiresEpoch {
		return time.Duration(expiresEpoch-now) * time.Millisecond
	}

	return 0
}

func (e *ExpiringLRUCache[T]) TotalCount() (count int) {
	return e.lru.Len()
}

func (e *ExpiringLRUCache[T]) Clear() {
	e.lru.Purge()
}
