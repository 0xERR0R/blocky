package metrics

import (
	"github.com/0xERR0R/blocky/config"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//nolint:gochecknoglobals
var reg = prometheus.NewRegistry()

// RegisterMetric registers prometheus collector
func RegisterMetric(c prometheus.Collector) {
	_ = reg.Register(c)
}

// Start starts prometheus endpoint
func Start(router *chi.Mux, cfg config.Metrics) {
	if cfg.Enable {
		_ = reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		_ = reg.Register(collectors.NewGoCollector())
		router.Handle(cfg.Path, promhttp.InstrumentMetricHandler(reg,
			promhttp.HandlerFor(reg, promhttp.HandlerOpts{})))
	}
}
