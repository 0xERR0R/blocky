package expirationcache

import (
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
	lru             *lru.Cache
}

type CacheOption[T any] func(c *ExpiringLRUCache[T])

func WithCleanUpInterval[T any](d time.Duration) CacheOption[T] {
	return func(e *ExpiringLRUCache[T]) {
		e.cleanUpInterval = d
	}
}

// OnExpirationCallback will be called just before an element gets expired and will
// be removed from cache. This function can return new value and TTL to leave the
// element in the cache or nil to remove it
type OnExpirationCallback[T any] func(key string) (val *T, ttl time.Duration)

func WithOnExpiredFn[T any](fn OnExpirationCallback[T]) CacheOption[T] {
	return func(c *ExpiringLRUCache[T]) {
		c.preExpirationFn = fn
	}
}

func WithMaxSize[T any](size uint) CacheOption[T] {
	return func(c *ExpiringLRUCache[T]) {
		if size > 0 {
			l, _ := lru.New(int(size))
			c.lru = l
		}
	}
}

func NewCache[T any](options ...CacheOption[T]) *ExpiringLRUCache[T] {
	l, _ := lru.New(defaultSize)
	c := &ExpiringLRUCache[T]{
		cleanUpInterval: defaultCleanUpInterval,
		preExpirationFn: func(key string) (val *T, ttl time.Duration) {
			return nil, 0
		},
		lru: l,
	}

	for _, opt := range options {
		opt(c)
	}

	go periodicCleanup(c)

	return c
}

func periodicCleanup[T any](c *ExpiringLRUCache[T]) {
	ticker := time.NewTicker(c.cleanUpInterval)
	defer ticker.Stop()

	for {
		<-ticker.C
		c.cleanUp()
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
			newVal, newTTL := e.preExpirationFn(key)
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
}

func (e *ExpiringLRUCache[T]) Get(key string) (val *T, ttl time.Duration) {
	el, found := e.lru.Get(key)

	if found {
		return el.(*element[T]).val, calculateRemainTTL(el.(*element[T]).expiresEpochMs)
	}

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
