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
