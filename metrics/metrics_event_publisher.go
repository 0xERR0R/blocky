package metrics

import (
	"fmt"
	"time"

	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/lists"
	"github.com/0xERR0R/blocky/util"

	"github.com/prometheus/client_golang/prometheus"
)

// RegisterEventListeners registers all metric handlers by the event bus
func RegisterEventListeners() {
	registerBlockingEventListeners()
	registerCachingEventListeners()
}

func registerBlockingEventListeners() {
	denylistCnt := denylistGauge()

	allowlistCnt := allowlistGauge()

	lastListGroupRefresh := lastListGroupRefresh()

	RegisterMetric(denylistCnt)
	RegisterMetric(allowlistCnt)
	RegisterMetric(lastListGroupRefresh)

	subscribe(evt.BlockingCacheGroupChanged, func(listType lists.ListCacheType, groupName string, cnt int) {
		lastListGroupRefresh.Set(float64(time.Now().Unix()))

		switch listType {
		case lists.ListCacheTypeDenylist:
			denylistCnt.WithLabelValues(groupName).Set(float64(cnt))
		case lists.ListCacheTypeAllowlist:
			allowlistCnt.WithLabelValues(groupName).Set(float64(cnt))
		}
	})
}

func denylistGauge() *prometheus.GaugeVec {
	denylistCnt := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "blocky_denylist_cache_entries",
			Help: "Number of entries in the denylist cache",
		}, []string{"group"},
	)

	return denylistCnt
}

func allowlistGauge() *prometheus.GaugeVec {
	allowlistCnt := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "blocky_allowlist_cache_entries",
			Help: "Number of entries in the allowlist cache",
		}, []string{"group"},
	)

	return allowlistCnt
}

func lastListGroupRefresh() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "blocky_last_list_group_refresh_timestamp_seconds",
			Help: "Timestamp of last list refresh",
		},
	)
}

func registerCachingEventListeners() {
	failedDownloadCount := failedDownloadCount()

	RegisterMetric(failedDownloadCount)

	subscribe(evt.CachingFailedDownloadChanged, func(_ string) {
		failedDownloadCount.Inc()
	})
}

func failedDownloadCount() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Name: "blocky_failed_downloads_total",
		Help: "Failed download counter",
	})
}

func subscribe(topic string, fn any) {
	util.FatalOnError(fmt.Sprintf("can't subscribe topic '%s'", topic), evt.Bus().Subscribe(topic, fn))
}
