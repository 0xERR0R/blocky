package metrics

import (
	"github.com/0xERR0R/blocky/config"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//nolint:gochecknoglobals
var Reg = prometheus.NewRegistry()

//nolint:gochecknoglobals
var (
	ConfigReloadTotal = func() *prometheus.CounterVec {
		c := prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "blocky_config_reload_total",
				Help: "Total number of config reload attempts",
			},
			[]string{"status"},
		)
		RegisterMetric(c)
		// Pre-initialize label values so the metric appears in the registry immediately
		c.WithLabelValues("success")
		c.WithLabelValues("failed")

		return c
	}()

	ConfigReloadTimestamp = func() prometheus.Gauge {
		g := prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "blocky_config_reload_timestamp",
				Help: "Unix timestamp of the last successful config reload",
			},
		)
		RegisterMetric(g)

		return g
	}()
)

// RegisterMetric registers prometheus collector
func RegisterMetric(c prometheus.Collector) {
	_ = Reg.Register(c)
}

// Start starts prometheus endpoint
func Start(router *chi.Mux, cfg config.Metrics) {
	if cfg.Enable {
		_ = Reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		_ = Reg.Register(collectors.NewGoCollector())
		router.Handle(cfg.Path, promhttp.InstrumentMetricHandler(Reg,
			promhttp.HandlerFor(Reg, promhttp.HandlerOpts{})))
	}
}
