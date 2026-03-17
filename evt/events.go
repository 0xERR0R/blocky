// Package evt provides a global event bus for list management notifications.
//
// The event bus is used exclusively for list cache change notifications:
//   - BlockingCacheGroupChanged: notifies when blocklist/allowlist cache groups are updated
//   - CachingFailedDownloadChanged: notifies when external list downloads fail
//
// Note: Lifecycle events (ApplicationStarted) and resolver metrics events have been
// removed as part of the metrics refactor. Those now use direct interfaces (PostStarter)
// and direct Prometheus metrics emission instead.
//
// Redis cross-instance synchronization does NOT use this event bus - it uses dedicated
// Go channels (redisClient.EnabledChannel, redisClient.CacheChannel).
package evt

import (
	"github.com/asaskevich/EventBus"
)

const (
	// BlockingCacheGroupChanged fires, if a list group is changed. Parameter: list type, group name, element count
	BlockingCacheGroupChanged = "blocking:cachingGroupChanged"

	// CachingFailedDownloadChanged fires, if a download of a blocking list or hosts file fails
	CachingFailedDownloadChanged = "caching:failedDownload"
)

//nolint:gochecknoglobals
var evtBus = EventBus.New()

// Bus returns the global bus instance
func Bus() EventBus.Bus {
	return evtBus
}
