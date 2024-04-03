package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

//nolint:gochecknoglobals
var reg = prometheus.NewRegistry()

// RegisterMetric registers prometheus collector
func RegisterMetric(c prometheus.Collector) {
	_ = reg.Register(c)
}

func StartCollection() {
	_ = reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	_ = reg.Register(collectors.NewGoCollector())

	registerEventListeners()
}
