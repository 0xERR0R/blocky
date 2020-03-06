package metrics

import (
	"blocky/config"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// nolint
var reg = prometheus.NewRegistry()

// nolint
var enabled bool

func RegisterMetric(c prometheus.Collector) {
	_ = reg.Register(c)
}

func Start(cfg config.PrometheusConfig) {
	enabled = cfg.Enable

	if cfg.Enable {
		reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
		reg.MustRegister(prometheus.NewGoCollector())
		http.Handle(cfg.Path, promhttp.InstrumentMetricHandler(reg,
			promhttp.HandlerFor(reg, promhttp.HandlerOpts{})))
	}
}

func IsEnabled() bool {
	return enabled
}
