package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"time"

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
	"github.com/go-chi/cors"
	"github.com/miekg/dns"
)

const (
	dohMessageLimit   = 512
	contentTypeHeader = "content-type"
	dnsContentType    = "application/dns-message"
	htmlContentType   = "text/html; charset=UTF-8"
	yamlContentType   = "text/yaml"
	corsMaxAge        = 5 * time.Minute
)

func secureHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("strict-transport-security", "max-age=63072000")
		w.Header().Set("x-frame-options", "DENY")
		w.Header().Set("x-content-type-options", "nosniff")
		w.Header().Set("x-xss-protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

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

func (s *Server) registerAPIEndpoints(router *chi.Mux) error {
	const pathDohQuery = "/dns-query"

	openAPIImpl, err := s.createOpenAPIInterfaceImpl()
	if err != nil {
		return err
	}

	api.RegisterOpenAPIEndpoints(router, openAPIImpl)

	router.Get(pathDohQuery, s.dohGetRequestHandler)
	router.Get(pathDohQuery+"/", s.dohGetRequestHandler)
	router.Get(pathDohQuery+"/{clientID}", s.dohGetRequestHandler)
	router.Post(pathDohQuery, s.dohPostRequestHandler)
	router.Post(pathDohQuery+"/", s.dohPostRequestHandler)
	router.Post(pathDohQuery+"/{clientID}", s.dohPostRequestHandler)

	return nil
}

func (s *Server) dohGetRequestHandler(rw http.ResponseWriter, req *http.Request) {
	dnsParam, ok := req.URL.Query()["dns"]
	if !ok || len(dnsParam[0]) < 1 {
		http.Error(rw, "dns param is missing", http.StatusBadRequest)

		return
	}

	rawMsg, err := base64.RawURLEncoding.DecodeString(dnsParam[0])
	if err != nil {
		http.Error(rw, "wrong message format", http.StatusBadRequest)

		return
	}

	if len(rawMsg) > dohMessageLimit {
		http.Error(rw, "URI Too Long", http.StatusRequestURITooLong)

		return
	}

	s.processDohMessage(rawMsg, rw, req)
}

func (s *Server) dohPostRequestHandler(rw http.ResponseWriter, req *http.Request) {
	contentType := req.Header.Get("Content-type")
	if contentType != dnsContentType {
		http.Error(rw, "unsupported content type", http.StatusUnsupportedMediaType)

		return
	}

	rawMsg, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	if len(rawMsg) > dohMessageLimit {
		http.Error(rw, "Payload Too Large", http.StatusRequestEntityTooLarge)

		return
	}

	s.processDohMessage(rawMsg, rw, req)
}

func (s *Server) processDohMessage(rawMsg []byte, rw http.ResponseWriter, req *http.Request) {
	msg := new(dns.Msg)

	if err := msg.Unpack(rawMsg); err != nil {
		logger().Error("can't deserialize message: ", err)
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	clientID := chi.URLParam(req, "clientID")
	if clientID == "" {
		clientID = extractClientIDFromHost(req.Host)
	}

	r := newRequest(util.HTTPClientIP(req), clientID, model.RequestProtocolTCP, msg)

	resResponse, err := s.resolve(req.Context(), r)
	if err != nil {
		logAndResponseWithError(err, "unable to process query: ", rw)

		return
	}

	b, err := resResponse.Res.Pack()
	if err != nil {
		logAndResponseWithError(err, "can't serialize message: ", rw)

		return
	}

	rw.Header().Set("content-type", dnsContentType)

	_, err = rw.Write(b)
	logAndResponseWithError(err, "can't write response: ", rw)
}

func (s *Server) Query(
	ctx context.Context, serverHost string, clientIP net.IP, question string, qType dns.Type,
) (*model.Response, error) {
	dnsRequest := util.NewMsgWithQuestion(question, qType)
	r := newRequest(clientIP, extractClientIDFromHost(serverHost), model.RequestProtocolTCP, dnsRequest)

	return s.resolve(ctx, r)
}

func createHTTPSRouter(cfg *config.Config) *chi.Mux {
	router := chi.NewRouter()

	configureSecureHeaderHandler(router)

	registerHandlers(cfg, router)

	return router
}

func createHTTPRouter(cfg *config.Config) *chi.Mux {
	router := chi.NewRouter()

	registerHandlers(cfg, router)

	return router
}

func registerHandlers(cfg *config.Config, router *chi.Mux) {
	configureCorsHandler(router)

	configureDebugHandler(router)

	configureDocsHandler(router)

	configureStaticAssetsHandler(router)

	configureRootHandler(cfg, router)
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

func configureSecureHeaderHandler(router *chi.Mux) {
	router.Use(secureHeader)
}

func configureDebugHandler(router *chi.Mux) {
	router.Mount("/debug", middleware.Profiler())
}

func configureCorsHandler(router *chi.Mux) {
	crs := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           int(corsMaxAge.Seconds()),
	})
	router.Use(crs.Handler)
}
