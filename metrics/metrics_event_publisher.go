package metrics

import (
	"fmt"

	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/util"

	"github.com/prometheus/client_golang/prometheus"
)

// RegisterEventListeners registers all metric handlers by the event bus
func RegisterEventListeners() {
	registerBlockingEventListeners()
	registerCachingEventListeners()
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

	lastListGroupRefresh := lastListGroupRefresh()

	RegisterMetric(lastListGroupRefresh)
}

func enabledGauge() prometheus.Gauge {
	enabledGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "blocky_blocking_enabled",
		Help: "Blocking status",
	})
	enabledGauge.Set(1)

	return enabledGauge
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
	entryCount := cacheEntryCount()
	prefetchDomainCount := prefetchDomainCacheCount()
	prefetchCount := domainPrefetchCount()
	prefetchHitCount := domainPrefetchHitCount()

	RegisterMetric(entryCount)
	RegisterMetric(prefetchDomainCount)
	RegisterMetric(prefetchCount)
	RegisterMetric(prefetchHitCount)

	subscribe(evt.CachingDomainsToPrefetchCountChanged, func(cnt int) {
		prefetchDomainCount.Set(float64(cnt))
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
}

func domainPrefetchCount() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "blocky_prefetches_total",
			Help: "Prefetch counter",
		},
	)
}

func domainPrefetchHitCount() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "blocky_prefetch_hits_total",
			Help: "Prefetch hit counter",
		},
	)
}

func cacheEntryCount() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "blocky_cache_entries",
			Help: "Number of entries in cache",
		},
	)
}

func prefetchDomainCacheCount() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "blocky_prefetch_domain_name_cache_entries",
			Help: "Number of entries in domain cache",
		},
	)
}

func subscribe(topic string, fn interface{}) {
	util.FatalOnError(fmt.Sprintf("can't subscribe topic '%s'", topic), evt.Bus().Subscribe(topic, fn))
}
