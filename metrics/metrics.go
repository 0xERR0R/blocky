package metrics

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//nolint:gochecknoglobals
var (
	Reg             = prometheus.NewRegistry()
	buildInfoMetric *prometheus.GaugeVec
)

//nolint:gochecknoinits
func init() {
	buildInfoMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "blocky_build_info",
			Help: "Version number and build info",
		},
		[]string{"version", "build_time"},
	)
	RegisterMetric(buildInfoMetric)
	// Set build info immediately with version and build time from util package
	buildInfoMetric.WithLabelValues(util.Version, util.BuildTime).Set(1)
}

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
