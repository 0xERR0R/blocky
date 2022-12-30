package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/config"
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
	jsonContentType   = "application/json"
	htmlContentType   = "text/html; charset=UTF-8"
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

func (s *Server) registerAPIEndpoints(router *chi.Mux) {
	router.Post(api.PathQueryPath, s.apiQuery)

	router.Get(api.PathDohQuery, s.dohGetRequestHandler)
	router.Get(api.PathDohQuery+"/", s.dohGetRequestHandler)
	router.Get(api.PathDohQuery+"/{clientID}", s.dohGetRequestHandler)
	router.Post(api.PathDohQuery, s.dohPostRequestHandler)
	router.Post(api.PathDohQuery+"/", s.dohPostRequestHandler)
	router.Post(api.PathDohQuery+"/{clientID}", s.dohPostRequestHandler)
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

	r := newRequest(net.ParseIP(extractIP(req)), model.RequestProtocolTCP, clientID, msg)

	resResponse, err := s.queryResolver.Resolve(r)
	if err != nil {
		logAndResponseWithError(err, "unable to process query: ", rw)

		return
	}

	response := new(dns.Msg)
	response.SetReply(msg)
	// enable compression
	resResponse.Res.Compress = true

	b, err := resResponse.Res.Pack()
	if err != nil {
		logAndResponseWithError(err, "can't serialize message: ", rw)

		return
	}

	rw.Header().Set("content-type", dnsContentType)

	_, err = rw.Write(b)
	logAndResponseWithError(err, "can't write response: ", rw)
}

func extractIP(r *http.Request) string {
	hostPort := r.Header.Get("X-FORWARDED-FOR")

	if hostPort == "" {
		hostPort = r.RemoteAddr
	}

	hostPort = strings.ReplaceAll(hostPort, "[", "")
	hostPort = strings.ReplaceAll(hostPort, "]", "")
	index := strings.LastIndex(hostPort, ":")

	if index >= 0 {
		return hostPort[:index]
	}

	return hostPort
}

// apiQuery is the http endpoint to perform a DNS query
// @Summary Performs DNS query
// @Description Performs DNS query
// @Tags query
// @Accept  json
// @Produce  json
// @Param query body api.QueryRequest true "query data"
// @Success 200 {object} api.QueryResult "query was executed"
// @Failure 400   "Wrong request format"
// @Router /query [post]
func (s *Server) apiQuery(rw http.ResponseWriter, req *http.Request) {
	var queryRequest api.QueryRequest

	rw.Header().Set(contentTypeHeader, jsonContentType)

	err := json.NewDecoder(req.Body).Decode(&queryRequest)
	if err != nil {
		logAndResponseWithError(err, "can't read request: ", rw)

		return
	}

	// validate query type
	qType := dns.Type(dns.StringToType[queryRequest.Type])
	if qType == dns.Type(dns.TypeNone) {
		err = fmt.Errorf("unknown query type '%s'", queryRequest.Type)
		logAndResponseWithError(err, "unknown query type: ", rw)

		return
	}

	query := queryRequest.Query

	// append dot
	if !strings.HasSuffix(query, ".") {
		query += "."
	}

	dnsRequest := util.NewMsgWithQuestion(query, qType)
	r := createResolverRequest(nil, dnsRequest)

	response, err := s.queryResolver.Resolve(r)
	if err != nil {
		logAndResponseWithError(err, "unable to process query: ", rw)

		return
	}

	jsonResponse, err := json.Marshal(api.QueryResult{
		Reason:       response.Reason,
		ResponseType: response.RType.String(),
		Response:     util.AnswerToString(response.Res.Answer),
		ReturnCode:   dns.RcodeToString[response.Res.Rcode],
	})
	if err != nil {
		logAndResponseWithError(err, "unable to marshal response: ", rw)

		return
	}

	_, err = rw.Write(jsonResponse)
	logAndResponseWithError(err, "unable to write response: ", rw)
}

func createHTTPSRouter(cfg *config.Config) *chi.Mux {
	router := chi.NewRouter()

	configureSecureHeaderHandler(router)

	configureCorsHandler(router)

	configureDebugHandler(router)

	configureRootHandler(cfg, router)

	return router
}

func createRouter(cfg *config.Config) *chi.Mux {
	router := chi.NewRouter()

	configureCorsHandler(router)

	configureDebugHandler(router)

	configureRootHandler(cfg, router)

	return router
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

		swaggerVersion := "master"
		if util.Version != "undefined" {
			swaggerVersion = util.Version
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
				URL: fmt.Sprintf(
					"https://htmlpreview.github.io/?https://github.com/0xERR0R/blocky/blob/%s/docs/swagger.html",
					swaggerVersion,
				),
				Title: "Swagger Rest API Documentation (Online @GitHub)",
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
