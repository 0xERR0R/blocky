package expirationcache

import "time"

type ExpiringCache[T any] interface {
	// Put adds the value to the cache unter the passed key with expiration. If expiration <=0, entry will NOT be cached
	Put(key string, val *T, expiration time.Duration)

	// Get returns the value of cached entry with remained TTL. If entry is not cached, returns nil
	Get(key string) (val *T, expiration time.Duration)

	// TotalCount returns the total count of valid (not expired) elements
	TotalCount() int

	// Clear removes all cache entries
	Clear()
}
