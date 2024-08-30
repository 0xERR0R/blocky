package server

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"

	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/resolver"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/docs"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/0xERR0R/blocky/web"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/miekg/dns"
)

const (
	dohMessageLimit   = 512
	contentTypeHeader = "content-type"
	dnsContentType    = "application/dns-message"
	htmlContentType   = "text/html; charset=UTF-8"
	yamlContentType   = "text/yaml"
)

func (s *Server) createOpenAPIInterfaceImpl() (impl api.StrictServerInterface, err error) {
	bControl, err := resolver.GetFromChainWithType[api.BlockingControl](s.queryResolver)
	if err != nil {
		return nil, fmt.Errorf("no blocking API implementation found %w", err)
	}

	refresher, err := resolver.GetFromChainWithType[api.ListRefresher](s.queryResolver)
	if err != nil {
		return nil, fmt.Errorf("no refresh API implementation found %w", err)
	}

	cacheControl, err := resolver.GetFromChainWithType[api.CacheControl](s.queryResolver)
	if err != nil {
		return nil, fmt.Errorf("no cache API implementation found %w", err)
	}

	return api.NewOpenAPIInterfaceImpl(bControl, s, refresher, cacheControl), nil
}

func (s *Server) Query(
	ctx context.Context, serverHost string, clientIP net.IP, question string, qType dns.Type,
) (*model.Response, error) {
	msg := util.NewMsgWithQuestion(question, qType)
	clientID := extractClientIDFromHost(serverHost)

	ctx, req := newRequest(ctx, clientIP, clientID, model.RequestProtocolTCP, msg)

	return s.resolve(ctx, req)
}

func createHTTPRouter(cfg *config.Config, openAPIImpl api.StrictServerInterface) *chi.Mux {
	router := chi.NewRouter()

	api.RegisterOpenAPIEndpoints(router, openAPIImpl)

	configureDebugHandler(router)

	configureDocsHandler(router)

	configureStaticAssetsHandler(router)

	configureRootHandler(cfg, router)

	metrics.Start(router, cfg.Prometheus)

	return router
}

func configureDocsHandler(router *chi.Mux) {
	router.Get("/docs/openapi.yaml", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(contentTypeHeader, yamlContentType)
		_, err := writer.Write([]byte(docs.OpenAPI))
		logAndResponseWithError(err, "can't write OpenAPI definition file: ", writer)
	})
}

func configureStaticAssetsHandler(router *chi.Mux) {
	assets, err := web.Assets()
	util.FatalOnError("unable to load static asset files", err)

	fs := http.FileServer(http.FS(assets))
	router.Handle("/static/*", http.StripPrefix("/static/", fs))
}

func configureRootHandler(cfg *config.Config, router *chi.Mux) {
	router.Get("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(contentTypeHeader, htmlContentType)

		t := template.New("index")

		_, _ = t.Parse(web.IndexTmpl)

		type HandlerLink struct {
			URL   string
			Title string
		}

		type PageData struct {
			Links     []HandlerLink
			Version   string
			BuildTime string
		}

		pd := PageData{
			Links:     nil,
			Version:   util.Version,
			BuildTime: util.BuildTime,
		}

		pd.Links = []HandlerLink{
			{
				URL:   "/docs/openapi.yaml",
				Title: "Rest API Documentation (OpenAPI)",
			},
			{
				URL:   "/static/rapidoc.html",
				Title: "Interactive Rest API Documentation (RapiDoc)",
			},
			{
				URL:   "/debug/",
				Title: "Go Profiler",
			},
		}

		if cfg.Prometheus.Enable {
			pd.Links = append(pd.Links, HandlerLink{
				URL:   cfg.Prometheus.Path,
				Title: "Prometheus endpoint",
			})
		}

		err := t.Execute(writer, pd)
		logAndResponseWithError(err, "can't write index template: ", writer)
	})
}

func logAndResponseWithError(err error, message string, writer http.ResponseWriter) {
	if err != nil {
		log.Log().Error(message, log.EscapeInput(err.Error()))
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

func configureDebugHandler(router *chi.Mux) {
	router.Mount("/debug", middleware.Profiler())
}
