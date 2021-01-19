package evt

import (
	"github.com/asaskevich/EventBus"
)

const (
	// BlockingEnabledEvent fires if blocking status will be changed. Parameter: boolean (enabled = true)
	BlockingEnabledEvent = "blocking:enabled"

	// BlockingCacheGroupChanged fires, if a list group is changed. Parameter: list type, group name, element count
	BlockingCacheGroupChanged = "blocking:cachingGroupChanged"

	// CachingDomainPrefetched fires if a domain will be prefetched, Parameter: domain name
	CachingDomainPrefetched = "caching:prefetched"

	// CachingResultCacheChanged fires if a result cache was changed, Parameter: new cache size
	CachingResultCacheChanged = "caching:resultCacheChanged"

	// CachingResultCacheHit fires, if a query result was found in the cache, Parameter: domain name
	CachingResultCacheHit = "caching:cacheHit"

	// CachingResultCacheMiss fires, if a query result was not found in the cache, Parameter: domain name
	CachingResultCacheMiss = "caching:cacheMiss"

	// CachingDomainsToPrefetchCountChanged fires, if a number of domains being prefetched changed, Parameter: new count
	CachingDomainsToPrefetchCountChanged = "caching:domainsToPrefetchCountChanged"
)

// nolint
var evtBus = EventBus.New()

func Bus() EventBus.Bus {
	return evtBus
}
