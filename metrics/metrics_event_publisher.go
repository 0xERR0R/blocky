package metrics

import (
	"context"
	"time"

	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/lists"

	"github.com/prometheus/client_golang/prometheus"
)

// RegisterEventListeners registers all metric handlers by the event bus
func RegisterEventListeners(bus *evt.Bus) {
	registerBlockingEventListeners(bus)
	registerCachingEventListeners(bus)
	registerApplicationEventListeners(bus)
}

func registerApplicationEventListeners(bus *evt.Bus) {
	v := versionNumberGauge()
	RegisterMetric(v)

	evt.Subscribe(bus, "metrics:app-started", func(_ context.Context, e evt.AppStartedEvent) {
		v.WithLabelValues(e.Version, e.BuildTime).Set(1)
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

func registerBlockingEventListeners(bus *evt.Bus) {
	enabledGauge := enabledGauge()

	RegisterMetric(enabledGauge)

	evt.Subscribe(bus, "metrics:blocking-enabled", func(_ context.Context, e evt.BlockingEnabledEvent) {
		if e.Enabled {
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

	evt.Subscribe(bus, "metrics:blocking-cache-group", func(_ context.Context, e evt.BlockingCacheGroupChangedEvent) {
		lastListGroupRefresh.Set(float64(time.Now().Unix()))

		switch e.ListType {
		case lists.ListCacheTypeDenylist.String():
			denylistCnt.WithLabelValues(e.GroupName).Set(float64(e.Count))
		case lists.ListCacheTypeAllowlist.String():
			allowlistCnt.WithLabelValues(e.GroupName).Set(float64(e.Count))
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

func registerCachingEventListeners(bus *evt.Bus) {
	entryCount := cacheEntryCount()
	prefetchDomainCount := prefetchDomainCacheCount()
	prefetchCount := domainPrefetchCount()
	prefetchHitCount := domainPrefetchHitCount()
	failedDownloadCount := failedDownloadCount()

	RegisterMetric(entryCount)
	RegisterMetric(prefetchDomainCount)
	RegisterMetric(prefetchCount)
	RegisterMetric(prefetchHitCount)
	RegisterMetric(failedDownloadCount)

	evt.Subscribe(bus, "metrics:prefetch-count", func(_ context.Context, e evt.CachingDomainsToPrefetchCountChangedEvent) {
		prefetchDomainCount.Set(float64(e.Count))
	})

	evt.Subscribe(bus, "metrics:prefetched", func(_ context.Context, _ evt.CachingDomainPrefetchedEvent) {
		prefetchCount.Inc()
	})

	evt.Subscribe(bus, "metrics:prefetch-hit", func(_ context.Context, _ evt.CachingPrefetchCacheHitEvent) {
		prefetchHitCount.Inc()
	})

	evt.Subscribe(bus, "metrics:result-cache-size", func(_ context.Context, e evt.CachingResultCacheChangedEvent) {
		entryCount.Set(float64(e.Size))
	})

	evt.Subscribe(bus, "metrics:failed-download", func(_ context.Context, _ evt.CachingFailedDownloadEvent) {
		failedDownloadCount.Inc()
	})
}

func failedDownloadCount() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Name: "blocky_failed_downloads_total",
		Help: "Failed download counter",
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
