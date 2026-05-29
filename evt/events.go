package evt

import (
	"time"

	"github.com/asaskevich/EventBus"
)

// ---------------------------------------------------------------------------
// Legacy string-based event bus. Will be removed in Task 9 once all callers
// have migrated to the typed Bus in bus.go.
// ---------------------------------------------------------------------------

const (
	// BlockingEnabledTopic fires if blocking status will be changed. Parameter: boolean (enabled = true)
	// Renamed from BlockingEnabledEvent to free that identifier for the new typed payload struct.
	BlockingEnabledTopic = "blocking:enabled"

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

// LegacyBus returns the global legacy bus instance.
//
// Deprecated: use the typed Bus from bus.go instead. Will be removed once all
// callers migrate (see plan 2026-05-29-typed-event-bus.md, Task 9).
func LegacyBus() EventBus.Bus {
	return evtBus
}

// ---------------------------------------------------------------------------
// Typed event payloads. Used by the typed Bus in bus.go.
// ---------------------------------------------------------------------------

// BlockingState carries the full blocking state for cross-instance sync.
type BlockingState struct {
	Enabled  bool          `json:"enabled"`
	Duration time.Duration `json:"duration,omitempty"`
	Groups   []string      `json:"groups,omitempty"`
}

// AppStartedEvent fires once when the application is fully up.
type AppStartedEvent struct {
	Version   string
	BuildTime string
}

// BlockingEnabledEvent fires when blocking is enabled or disabled.
type BlockingEnabledEvent struct {
	Enabled bool
}

// BlockingStateChangedEvent fires when local blocking state changes (consumed by the Redis bridge).
type BlockingStateChangedEvent struct {
	State BlockingState
}

// BlockingStateChangedRemoteEvent fires when blocking state changes on a remote instance (delivered via Redis).
type BlockingStateChangedRemoteEvent struct {
	State BlockingState
}

// BlockingCacheGroupChangedEvent fires when a denylist or allowlist group is refreshed.
// ListType is the string form of lists.ListCacheType ("denylist" or "allowlist").
// String is used (rather than lists.ListCacheType) to keep evt free of an
// import-cycle-creating dependency on the lists package.
type BlockingCacheGroupChangedEvent struct {
	ListType  string
	GroupName string
	Count     int
}

// CachingDomainPrefetchedEvent fires when a domain is prefetched.
type CachingDomainPrefetchedEvent struct {
	Domain string
}

// CachingResultCacheChangedEvent fires when the result cache size changes.
type CachingResultCacheChangedEvent struct {
	Size int
}

// CachingPrefetchCacheHitEvent fires when a query result is served from the prefetch cache.
type CachingPrefetchCacheHitEvent struct {
	Domain string
}

// CachingDomainsToPrefetchCountChangedEvent fires when the number of prefetch-tracked domains changes.
type CachingDomainsToPrefetchCountChangedEvent struct {
	Count int
}

// CachingFailedDownloadEvent fires when a list/hosts-file download fails.
type CachingFailedDownloadEvent struct {
	URL string
}
