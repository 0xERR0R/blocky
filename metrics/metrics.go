package metrics

import (
	"blocky/config"

	"github.com/go-chi/chi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// nolint
var reg = prometheus.NewRegistry()

// RegisterMetric registers prometheus collector
func RegisterMetric(c prometheus.Collector) {
	_ = reg.Register(c)
}

// Start starts prometheus endpoint
func Start(router *chi.Mux, cfg config.PrometheusConfig) {
	if cfg.Enable {
		_ = reg.Register(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
		_ = reg.Register(prometheus.NewGoCollector())
		router.Handle(cfg.Path, promhttp.InstrumentMetricHandler(reg,
			promhttp.HandlerFor(reg, promhttp.HandlerOpts{})))
	}
}
