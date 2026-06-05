package evt

import (
	"time"
)

// Typed event payloads. Used by the typed Bus in bus.go.

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
