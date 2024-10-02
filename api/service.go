package api

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/service"
	"github.com/0xERR0R/blocky/util"
)

// Service implements service.HTTPService.
type Service struct {
	service.SimpleHTTP
}

func NewService(cfg config.APIService, server StrictServerInterface) *Service {
	endpoints := util.ConcatSlices(
		service.EndpointsFromAddrs(service.HTTPProtocol, cfg.Addrs.HTTP),
		service.EndpointsFromAddrs(service.HTTPSProtocol, cfg.Addrs.HTTPS),
	)

	s := &Service{
		SimpleHTTP: service.NewSimpleHTTP("API", endpoints),
	}

	registerOpenAPIEndpoints(s.Router(), server)

	return s
}
