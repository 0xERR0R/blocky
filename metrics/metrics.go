package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

//nolint:gochecknoglobals
var Reg = prometheus.NewRegistry()

// RegisterMetric registers prometheus collector
func RegisterMetric(c prometheus.Collector) {
	_ = Reg.Register(c)
}

func StartCollection() {
	_ = Reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	_ = Reg.Register(collectors.NewGoCollector())

	registerEventListeners()
}
