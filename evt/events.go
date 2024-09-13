package evt

import (
	"github.com/asaskevich/EventBus"
)

const (
	// BlockingEnabledEvent fires if blocking status will be changed. Parameter: boolean (enabled = true)
	BlockingEnabledEvent = "blocking:enabled"

	// CachingDomainPrefetched fires if a domain will be prefetched, Parameter: domain name
	CachingDomainPrefetched = "caching:prefetched"

	// CachingResultCacheChanged fires if a result cache was changed, Parameter: new cache size
	CachingResultCacheChanged = "caching:resultCacheChanged"

	// CachingPrefetchCacheHit fires if a query result was found in the prefetch cache, Parameter: domain name
	CachingPrefetchCacheHit = "caching:prefetchHit"

	// CachingDomainsToPrefetchCountChanged fires, if a number of domains being prefetched changed, Parameter: new count
	CachingDomainsToPrefetchCountChanged = "caching:domainsToPrefetchCountChanged"

	// ApplicationStarted fires on start of the application. Parameter: version number, build time
	ApplicationStarted = "application:started"
)

//nolint:gochecknoglobals
var evtBus = EventBus.New()

// Bus returns the global bus instance
func Bus() EventBus.Bus {
	return evtBus
}
