package expirationcache

import (
	"time"

	lru "github.com/hashicorp/golang-lru"
)

const (
	defaultCleanUpInterval = 10 * time.Second
	defaultSize            = 10_000
)

type element struct {
	val            interface{}
	expiresEpochMs int64
}

type ExpiringLRUCache struct {
	cleanUpInterval time.Duration
	preExpirationFn OnExpirationCallback
	lru             *lru.Cache
}

type CacheOption func(c *ExpiringLRUCache)

func WithCleanUpInterval(d time.Duration) CacheOption {
	return func(e *ExpiringLRUCache) {
		e.cleanUpInterval = d
	}
}

// OnExpirationCallback will be called just before an element gets expired and will
// be removed from cache. This function can return new value and TTL to leave the
// element in the cache or nil to remove it
type OnExpirationCallback func(key string) (val interface{}, ttl time.Duration)

func WithOnExpiredFn(fn OnExpirationCallback) CacheOption {
	return func(c *ExpiringLRUCache) {
		c.preExpirationFn = fn
	}
}

func WithMaxSize(size uint) CacheOption {
	return func(c *ExpiringLRUCache) {
		if size > 0 {
			l, _ := lru.New(int(size))
			c.lru = l
		}
	}
}

func NewCache(options ...CacheOption) *ExpiringLRUCache {
	l, _ := lru.New(defaultSize)
	c := &ExpiringLRUCache{
		cleanUpInterval: defaultCleanUpInterval,
		preExpirationFn: func(key string) (val interface{}, ttl time.Duration) {
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

func periodicCleanup(c *ExpiringLRUCache) {
	ticker := time.NewTicker(c.cleanUpInterval)
	defer ticker.Stop()

	for {
		<-ticker.C
		c.cleanUp()
	}
}

func (e *ExpiringLRUCache) cleanUp() {
	var expiredKeys []string

	// check for expired items and collect expired keys
	for _, k := range e.lru.Keys() {
		if v, ok := e.lru.Get(k); ok {
			if isExpired(v.(*element)) {
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

func (e *ExpiringLRUCache) Put(key string, val interface{}, ttl time.Duration) {
	if ttl <= 0 {
		// entry should be considered as already expired
		return
	}

	expiresEpochMs := time.Now().UnixMilli() + ttl.Milliseconds()

	el, found := e.lru.Get(key)
	if found {
		// update existing item
		el.(*element).val = val
		el.(*element).expiresEpochMs = expiresEpochMs
	} else {
		// add new item
		e.lru.Add(key, &element{
			val:            val,
			expiresEpochMs: expiresEpochMs,
		})
	}
}

func (e *ExpiringLRUCache) Get(key string) (val interface{}, ttl time.Duration) {
	el, found := e.lru.Get(key)

	if found {
		return el.(*element).val, calculateRemainTTL(el.(*element).expiresEpochMs)
	}

	return nil, 0
}

func isExpired(el *element) bool {
	return el.expiresEpochMs > 0 && time.Now().UnixMilli() > el.expiresEpochMs
}

func calculateRemainTTL(expiresEpoch int64) time.Duration {
	now := time.Now().UnixMilli()
	if now < expiresEpoch {
		return time.Duration(expiresEpoch-now) * time.Millisecond
	}

	return 0
}

func (e *ExpiringLRUCache) TotalCount() (count int) {
	for _, k := range e.lru.Keys() {
		if v, ok := e.lru.Get(k); ok {
			if !isExpired(v.(*element)) {
				count++
			}
		}
	}

	return count
}

func (e *ExpiringLRUCache) Clear() {
	e.lru.Purge()
}
