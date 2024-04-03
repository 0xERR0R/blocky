package metrics

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/service"
	"github.com/0xERR0R/blocky/util"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Service implements service.HTTPService.
type Service struct {
	service.SimpleHTTP
}

func NewService(cfg config.MetricsService, metricsCfg config.Metrics) *Service {
	endpoints := util.ConcatSlices(
		service.EndpointsFromAddrs(service.HTTPProtocol, cfg.Addrs.HTTP),
		service.EndpointsFromAddrs(service.HTTPSProtocol, cfg.Addrs.HTTPS),
	)

	if !metricsCfg.Enable || len(endpoints) == 0 {
		// Avoid setting up collectors and listeners
		return new(Service)
	}

	s := &Service{
		SimpleHTTP: service.NewSimpleHTTP("Metrics", endpoints),
	}

	s.Router().Handle(
		metricsCfg.Path,
		promhttp.InstrumentMetricHandler(reg, promhttp.HandlerFor(reg, promhttp.HandlerOpts{})),
	)

	return s
}
