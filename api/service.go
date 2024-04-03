package api

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/service"
	"github.com/0xERR0R/blocky/util"
	"github.com/go-chi/chi/v5"
)

// Service implements service.HTTPService.
type Service struct {
	service.HTTPInfo
}

func NewService(cfg config.APIService, server StrictServerInterface) *Service {
	endpoints := util.ConcatSlices(
		service.EndpointsFromAddrs(service.HTTPProtocol, cfg.Addrs.HTTP),
		service.EndpointsFromAddrs(service.HTTPSProtocol, cfg.Addrs.HTTPS),
	)

	s := &Service{
		HTTPInfo: service.HTTPInfo{
			Info: service.Info{
				Name:      "API",
				Endpoints: endpoints,
			},

			Mux: chi.NewMux(),
		},
	}

	registerOpenAPIEndpoints(s.Mux, server)

	return s
}

func (s *Service) Merge(other service.Service) (service.Merger, error) {
	return service.MergeHTTP(s, other)
}
