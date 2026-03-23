package evt

import (
	"time"

	"github.com/asaskevich/EventBus"
)

const (
	// BlockingEnabledEvent fires if blocking status will be changed. Parameter: boolean (enabled = true)
	BlockingEnabledEvent = "blocking:enabled"

	// BlockingStateChanged fires when blocking state changes locally (for Redis bridge).
	// Parameter: BlockingState
	BlockingStateChanged = "blocking:stateChanged"

	// BlockingStateChangedRemote fires when blocking state changes from a remote instance via Redis.
	// Parameter: BlockingState
	BlockingStateChangedRemote = "blocking:stateChangedRemote"

	// BlockingCacheGroupChanged fires, if a list group is changed. Parameter: list type, group name, element count
	BlockingCacheGroupChanged = "blocking:cachingGroupChanged"

	// CachingDomainPrefetched fires if a domain will be prefetched, Parameter: domain name
	CachingDomainPrefetched = "caching:prefetched"

	// CachingResultCacheChanged fires if a result cache was changed, Parameter: new cache size
	CachingResultCacheChanged = "caching:resultCacheChanged"

	// CachingPrefetchCacheHit fires if a query result was found in the prefetch cache, Parameter: domain name
	CachingPrefetchCacheHit = "caching:prefetchHit"

	// CachingDomainsToPrefetchCountChanged fires, if a number of domains being prefetched changed, Parameter: new count
	CachingDomainsToPrefetchCountChanged = "caching:domainsToPrefetchCountChanged"

	// CachingFailedDownloadChanged fires, if a download of a blocking list or hosts file fails
	CachingFailedDownloadChanged = "caching:failedDownload"

	// ApplicationStarted fires on start of the application. Parameter: version number, build time
	ApplicationStarted = "application:started"
)

//nolint:gochecknoglobals
var evtBus = EventBus.New()

// Bus returns the global bus instance
func Bus() EventBus.Bus {
	return evtBus
}

// BlockingState carries the full blocking state for cross-instance sync.
type BlockingState struct {
	Enabled  bool          `json:"enabled"`
	Duration time.Duration `json:"duration,omitempty"`
	Groups   []string      `json:"groups,omitempty"`
}
