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
	registerApplicationEventListeners()
}

func registerApplicationEventListeners() {
	v := versionNumberGauge()
	RegisterMetric(v)

	subscribe(evt.ApplicationStarted, func(version, buildTime string) {
		v.WithLabelValues(version, buildTime).Set(1)
	})
}

func versionNumberGauge() *prometheus.GaugeVec {
	denylistCnt := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "blocky_build_info",
			Help: "Version number and build info",
		}, []string{"version", "build_time"},
	)

	return denylistCnt
}

func registerBlockingEventListeners() {
	enabledGauge := enabledGauge()

	RegisterMetric(enabledGauge)

	subscribe(evt.BlockingEnabledEvent, func(enabled bool) {
		if enabled {
			enabledGauge.Set(1)
		} else {
			enabledGauge.Set(0)
		}
	})

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

func enabledGauge() prometheus.Gauge {
	enabledGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "blocky_blocking_enabled",
		Help: "Blocking status",
	})
	enabledGauge.Set(1)

	return enabledGauge
}

func denylistGauge() *prometheus.GaugeVec {
	denylistCnt := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "blocky_denylist_cache",
			Help: "Number of entries in the denylist cache",
		}, []string{"group"},
	)

	return denylistCnt
}

func allowlistGauge() *prometheus.GaugeVec {
	allowlistCnt := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "blocky_allowlist_cache",
			Help: "Number of entries in the allowlist cache",
		}, []string{"group"},
	)

	return allowlistCnt
}

func lastListGroupRefresh() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "blocky_last_list_group_refresh",
			Help: "Timestamp of last list refresh",
		},
	)
}

func registerCachingEventListeners() {
	entryCount := cacheEntryCount()
	prefetchDomainCount := prefetchDomainCacheCount()
	hitCount := cacheHitCount()
	missCount := cacheMissCount()
	prefetchCount := domainPrefetchCount()
	prefetchHitCount := domainPrefetchHitCount()
	failedDownloadCount := failedDownloadCount()

	RegisterMetric(entryCount)
	RegisterMetric(prefetchDomainCount)
	RegisterMetric(hitCount)
	RegisterMetric(missCount)
	RegisterMetric(prefetchCount)
	RegisterMetric(prefetchHitCount)
	RegisterMetric(failedDownloadCount)

	subscribe(evt.CachingDomainsToPrefetchCountChanged, func(cnt int) {
		prefetchDomainCount.Set(float64(cnt))
	})

	subscribe(evt.CachingResultCacheMiss, func(_ string) {
		missCount.Inc()
	})

	subscribe(evt.CachingResultCacheHit, func(_ string) {
		hitCount.Inc()
	})

	subscribe(evt.CachingDomainPrefetched, func(_ string) {
		prefetchCount.Inc()
	})

	subscribe(evt.CachingPrefetchCacheHit, func(_ string) {
		prefetchHitCount.Inc()
	})

	subscribe(evt.CachingResultCacheChanged, func(cnt int) {
		entryCount.Set(float64(cnt))
	})

	subscribe(evt.CachingFailedDownloadChanged, func(_ string) {
		failedDownloadCount.Inc()
	})
}

func failedDownloadCount() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Name: "blocky_failed_download_count",
		Help: "Failed download counter",
	})
}

func cacheHitCount() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "blocky_cache_hit_count",
			Help: "Cache hit counter",
		},
	)
}

func cacheMissCount() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "blocky_cache_miss_count",
			Help: "Cache miss counter",
		},
	)
}

func domainPrefetchCount() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "blocky_prefetch_count",
			Help: "Prefetch counter",
		},
	)
}

func domainPrefetchHitCount() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "blocky_prefetch_hit_count",
			Help: "Prefetch hit counter",
		},
	)
}

func cacheEntryCount() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "blocky_cache_entry_count",
			Help: "Number of entries in cache",
		},
	)
}

func prefetchDomainCacheCount() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "blocky_prefetch_domain_name_cache_count",
			Help: "Number of entries in domain cache",
		},
	)
}

func subscribe(topic string, fn interface{}) {
	util.FatalOnError(fmt.Sprintf("can't subscribe topic '%s'", topic), evt.Bus().Subscribe(topic, fn))
}
