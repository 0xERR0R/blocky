package server

import (
	"blocky/api"
	"blocky/config"
	"blocky/log"
	"blocky/resolver"
	"blocky/util"
	"blocky/web"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/miekg/dns"
)

const (
	dohMessageLimit = 512
	dnsContentType  = "application/dns-message"
)

func (s *Server) registerAPIEndpoints(router *chi.Mux) {
	router.Post(api.PathQueryPath, s.apiQuery)

	router.Get("/dns-query", s.dohGetRequestHandler)
	router.Post("/dns-query", s.dohPostRequestHandler)
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

func (s *Server) dohJsonGetRequestHandler(rw http.ResponseWriter, req *http.Request) {
	recname := req.URL.Query().Get("name")
	rectype := req.URL.Query().Get("type")
	if len(recname) < 1 {
		http.Error(rw, "dns param is missing", http.StatusBadRequest)

		return
	}
	rectypeint, err := strconv.Atoi(rectype)
	if err != nil {
		rectypeint = 255
	}

	type QuestionRec struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	}

	myquestion := QuestionRec{
		Name: recname,
		Type: rectypeint,
	}
	var m dns.Msg
	m.SetQuestion(dns.Fqdn(recname), uint16(rectypeint))
	msg, err := m.Pack()
	if err != nil {
		logger().Error("Failed to pack json request", err)
	}
	res := s.processJSONDNSMessage(msg, rw, req)

	type ResponseRecord struct {
		AD               bool          `json:"AD"`
		Additional       []interface{} `json:"Additional"`
		Answer           []dns.RR
		CD               bool        `json:"CD"`
		Question         QuestionRec `json:"Question"`
		RA               bool        `json:"RA"`
		RD               bool        `json:"RD"`
		Status           int         `json:"Status"`
		TC               bool        `json:"TC"`
		EdnsClientSubnet string      `json:"edns_client_subnet"`
		Comment          string      `json:"Comment"`
	}

	status := 0
	if res.Res.Rcode != dns.RcodeSuccess {
		logger().Error(" *** invalid answer name %s after A query for %s\n", recname, recname)
		status = 1

	}

	responsejson := ResponseRecord{
		AD:       false,
		CD:       false,
		Answer:   res.Res.Answer,
		Question: myquestion,
		Status:   status,
		TC:       false,
		RD:       true,
		RA:       true,
	}

	jsonoutbyte, err := json.Marshal(responsejson)
	if err != nil {
		logger().Error("Error", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	} else {
		rw.Write(jsonoutbyte)
	}
}

func (s *Server) processJSONDNSMessage(rawMsg []byte, rw http.ResponseWriter, req *http.Request) *resolver.Response {
	msg := new(dns.Msg)
	err := msg.Unpack(rawMsg)

	if err != nil {
		logger().Error("can't deserialize message: ", err)
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return nil
	}

	r := newRequest(net.ParseIP(extractIP(req)), resolver.TCP, msg)

	resResponse, err := s.queryResolver.Resolve(r)

	if err != nil {
		logger().Error("unable to process query: ", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return resResponse
	}
	return resResponse

}

func (s *Server) dohPostRequestHandler(rw http.ResponseWriter, req *http.Request) {
	contentType := req.Header.Get("Content-type")
	if contentType != dnsContentType {
		http.Error(rw, "unsupported content type", http.StatusUnsupportedMediaType)

		return
	}

	rawMsg, err := ioutil.ReadAll(req.Body)
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
	err := msg.Unpack(rawMsg)

	if err != nil {
		logger().Error("can't deserialize message: ", err)
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	r := newRequest(net.ParseIP(extractIP(req)), resolver.TCP, msg)

	resResponse, err := s.queryResolver.Resolve(r)

	if err != nil {
		logger().Error("unable to process query: ", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	response := new(dns.Msg)
	response.SetReply(msg)

	b, err := resResponse.Res.Pack()
	if err != nil {
		logger().Error("can't serialize message: ", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}

	rw.Header().Set("content-type", dnsContentType)

	_, err = rw.Write(b)
	if err != nil {
		logger().Error("can't write response: ", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
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
	err := json.NewDecoder(req.Body).Decode(&queryRequest)

	if err != nil {
		logger().Error("can't read request: ", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	// validate query type
	qType := dns.StringToType[queryRequest.Type]
	if qType == dns.TypeNone {
		err = fmt.Errorf("unknown query type '%s'", queryRequest.Type)
		logger().Error(err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)

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
		logger().Error("unable to process query: ", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	jsonResponse, _ := json.Marshal(api.QueryResult{
		Reason:       response.Reason,
		ResponseType: response.RType.String(),
		Response:     util.AnswerToString(response.Res.Answer),
		ReturnCode:   dns.RcodeToString[response.Res.Rcode],
	})
	_, err = rw.Write(jsonResponse)

	if err != nil {
		logger().Error("unable to write response ", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}
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
		t := template.New("index")
		_, _ = t.Parse(web.IndexTmpl)

		type HandlerLink struct {
			URL   string
			Title string
		}
		var links = []HandlerLink{
			{
				URL:   "https://htmlpreview.github.io/?https://github.com/0xERR0R/blocky/blob/master/docs/swagger.html",
				Title: "Swagger Rest API Documentation (Online @GitHub)",
			},
			{
				URL:   "/debug/",
				Title: "Go Profiler",
			},
		}

		if cfg.Prometheus.Enable {
			links = append(links, HandlerLink{
				URL:   cfg.Prometheus.Path,
				Title: "Prometheus endpoint",
			})
		}

		err := t.Execute(writer, links)
		if err != nil {
			log.Log().Error("can't write index template: ", err)
			writer.WriteHeader(http.StatusInternalServerError)
		}
	})
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
		MaxAge:           300,
	})
	router.Use(crs.Handler)
}
