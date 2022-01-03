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

	// CachingPrefetchCacheHit fires if a query result was found in the prefetch cache, Parameter: domain name
	CachingPrefetchCacheHit = "caching:prefetchHit"

	// CachingResultCacheHit fires, if a query result was found in the cache, Parameter: domain name
	CachingResultCacheHit = "caching:cacheHit"

	// CachingResultCacheMiss fires, if a query result was not found in the cache, Parameter: domain name
	CachingResultCacheMiss = "caching:cacheMiss"

	// CachingDomainsToPrefetchCountChanged fires, if a number of domains being prefetched changed, Parameter: new count
	CachingDomainsToPrefetchCountChanged = "caching:domainsToPrefetchCountChanged"

	// CachingFailedDownloadChanged fires, if a download of a blocking list fails
	CachingFailedDownloadChanged = "caching:failedDownload"

	// ApplicationStarted fires on start of the application. Parameter: version number, build time
	ApplicationStarted = "application:started"
)

// nolint
var evtBus = EventBus.New()

// Bus returns the global bus instance
func Bus() EventBus.Bus {
	return evtBus
}
