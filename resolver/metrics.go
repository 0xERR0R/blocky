package resolver

import (
	"blocky/config"
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
)

type Metrics interface {
	RecordStats(request *Request, response *Response)
	Start()
}

type MetricsImpl struct {
	Gatherer   prometheus.Gatherer
	Registry   prometheus.Registerer
	cfg        config.PrometheusConfig
	cacheHit   prometheus.Counter
	cacheMiss  prometheus.Counter
	totalBlock prometheus.Counter
	totalQuery prometheus.Counter
}

func (m MetricsImpl) RecordStats(request *Request, response *Response) {
	m.totalQuery.Inc()

	if response.rType == CACHED {
		m.cacheHit.Inc()
	} else {
		// don't count blocks as misses since they can't be cached
		if response.rType == BLOCKED {
			m.totalBlock.Inc()
		} else {
			m.cacheMiss.Inc()
		}
	}
}

func cacheHitMetric() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_hit_total",
			Help: "Number of queries returned from cache",
		},
	)
}

func cacheMissMetrics() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_miss_total",
			Help: "Number of queries missed from cache",
		},
	)
}

func totalBlockMetric() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "blocked_total",
			Help: "Number of queries blocked",
		},
	)
}

func totalQueriesMetric() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "query_total",
			Help: "Number of total queries",
		},
	)
}

func (m MetricsImpl) Start() {
	if m.cfg.Enable {
		go func() {
			http.Handle(m.cfg.Path, promhttp.InstrumentMetricHandler(m.Registry,
				promhttp.HandlerFor(m.Gatherer, promhttp.HandlerOpts{})))
			log.Fatal(http.ListenAndServe(":"+strconv.Itoa(int(m.cfg.Port)), nil))
		}()
	}
}

func NewMetrics(cfg config.PrometheusConfig) Metrics {
	reg := prometheus.NewRegistry()

	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	reg.MustRegister(prometheus.NewGoCollector())

	cacheHit := cacheHitMetric()
	cacheMiss := cacheMissMetrics()
	totalBlock := totalBlockMetric()
	totalQuery := totalQueriesMetric()

	reg.MustRegister(cacheHit, cacheMiss, totalBlock, totalQuery)

	return MetricsImpl{
		Gatherer:   reg,
		Registry:   reg,
		cfg:        cfg,
		cacheMiss:  cacheMiss,
		cacheHit:   cacheHit,
		totalBlock: totalBlock,
		totalQuery: totalQuery,
	}
}
