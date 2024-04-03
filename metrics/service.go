package metrics

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/service"
	"github.com/0xERR0R/blocky/util"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Service implements service.HTTPService.
type Service struct {
	service.HTTPInfo
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
		HTTPInfo: service.HTTPInfo{
			Info: service.Info{
				Name:      "Metrics",
				Endpoints: endpoints,
			},

			Mux: chi.NewMux(),
		},
	}

	s.Mux.Handle(
		metricsCfg.Path,
		promhttp.InstrumentMetricHandler(reg, promhttp.HandlerFor(reg, promhttp.HandlerOpts{})),
	)

	return s
}

func (s *Service) Merge(other service.Service) (service.Merger, error) {
	return service.MergeHTTP(s, other)
}
