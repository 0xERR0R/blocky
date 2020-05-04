package server

import (
	"blocky/api"
	"blocky/config"
	"blocky/docs"
	"blocky/metrics"
	"blocky/resolver"
	"blocky/web"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"syscall"

	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"time"

	"blocky/util"
	"fmt"
	"net"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	httpSwagger "github.com/swaggo/http-swagger"
)

type Server struct {
	udpServer     *dns.Server
	tcpServer     *dns.Server
	httpListener  net.Listener
	queryResolver resolver.Resolver
	cfg           *config.Config
	httpMux       *chi.Mux
}

func logger() *logrus.Entry {
	return logrus.WithField("prefix", "server")
}

func NewServer(cfg *config.Config) (*Server, error) {
	udpHandler := dns.NewServeMux()
	tcpHandler := dns.NewServeMux()
	udpServer := &dns.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Net:     "udp",
		Handler: udpHandler,
		NotifyStartedFunc: func() {
			logger().Infof("udp server is up and running on port %d", cfg.Port)
		},
		UDPSize: 65535}
	tcpServer := &dns.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Net:     "tcp",
		Handler: tcpHandler,
		NotifyStartedFunc: func() {
			logger().Infof("tcp server is up and running on port %d", cfg.Port)
		},
	}

	var httpListener net.Listener

	router := createRouter(cfg)

	if cfg.HTTPPort > 0 {
		var err error
		if httpListener, err = net.Listen("tcp", fmt.Sprintf(":%d", cfg.HTTPPort)); err != nil {
			logger().Fatalf("start http listener on port %d failed: %v", cfg.HTTPPort, err)
		}

		metrics.Start(router, cfg.Prometheus)
	}

	queryResolver := resolver.Chain(
		resolver.NewClientNamesResolver(cfg.ClientLookup),
		resolver.NewQueryLoggingResolver(cfg.QueryLog),
		resolver.NewStatsResolver(),
		resolver.NewMetricsResolver(cfg.Prometheus),
		resolver.NewConditionalUpstreamResolver(cfg.Conditional),
		resolver.NewCustomDNSResolver(cfg.CustomDNS),
		resolver.NewBlockingResolver(router, cfg.Blocking),
		resolver.NewCachingResolver(cfg.Caching),
		resolver.NewParallelBestResolver(cfg.Upstream),
	)

	server := Server{
		udpServer:     udpServer,
		tcpServer:     tcpServer,
		queryResolver: queryResolver,
		cfg:           cfg,
		httpListener:  httpListener,
		httpMux:       router,
	}

	server.printConfiguration()

	server.registerDNSHandlers(udpHandler)
	server.registerDNSHandlers(tcpHandler)
	server.registerAPIEndpoints(router)

	return &server, nil
}

func (s *Server) registerDNSHandlers(handler *dns.ServeMux) {
	handler.HandleFunc(".", s.OnRequest)
	handler.HandleFunc("healthcheck.blocky", s.OnHealthCheck)
}

func createRouter(cfg *config.Config) *chi.Mux {
	router := chi.NewRouter()

	crs := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	})
	router.Use(crs.Handler)

	router.Mount("/debug", middleware.Profiler())

	router.Get("/swagger/*", func(writer http.ResponseWriter, request *http.Request) {
		// set swagger host with host from request
		docs.SwaggerInfo.Host = request.Host
		swaggerHandler := httpSwagger.Handler(
			httpSwagger.URL(fmt.Sprintf("http://%s/swagger/doc.json", request.Host)),
		)
		swaggerHandler.ServeHTTP(writer, request)
	})

	router.Get("/", func(writer http.ResponseWriter, request *http.Request) {
		t := template.New("index")
		_, _ = t.Parse(web.IndexTmpl)

		type HandlerLink struct {
			URL   string
			Title string
		}
		var links = []HandlerLink{
			{
				URL:   fmt.Sprintf("http://%s/swagger/", request.Host),
				Title: "Swagger Rest API Documentation",
			},
			{
				URL:   fmt.Sprintf("http://%s/debug/", request.Host),
				Title: "Go Profiler",
			},
		}

		if cfg.Prometheus.Enable {
			links = append(links, HandlerLink{
				URL:   fmt.Sprintf("http://%s%s", request.Host, cfg.Prometheus.Path),
				Title: "Prometheus endpoint",
			})
		}

		err := t.Execute(writer, links)
		if err != nil {
			logrus.Error("can't write index template: ", err)
			writer.WriteHeader(http.StatusInternalServerError)
		}
	})

	return router
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

func (s *Server) printConfiguration() {
	logger().Info("current configuration:")

	res := s.queryResolver
	for res != nil {
		logger().Infof("-> resolver: '%s'", resolver.Name(res))

		for _, c := range res.Configuration() {
			logger().Infof("     %s", c)
		}

		if c, ok := res.(resolver.ChainedResolver); ok {
			res = c.GetNext()
		} else {
			break
		}
	}

	logger().Infof("- DNS listening port: %d", s.cfg.Port)
	logger().Infof("- HTTP listening port: %d", s.cfg.HTTPPort)

	logger().Info("runtime information:")

	// force garbage collector
	runtime.GC()
	debug.FreeOSMemory()

	// gather memory stats
	var m runtime.MemStats

	runtime.ReadMemStats(&m)

	logger().Infof("MEM Alloc =        %10v MB", toMB(m.Alloc))
	logger().Infof("MEM HeapAlloc =    %10v MB", toMB(m.HeapAlloc))
	logger().Infof("MEM Sys =          %10v MB", toMB(m.Sys))
	logger().Infof("MEM NumGC =        %10v", m.NumGC)
	logger().Infof("RUN NumCPU =       %10d", runtime.NumCPU())
	logger().Infof("RUN NumGoroutine = %10d", runtime.NumGoroutine())
}

func toMB(b uint64) uint64 {
	return b / 1024 / 1024
}

func (s *Server) Start() {
	logger().Info("Starting server")

	go func() {
		if err := s.udpServer.ListenAndServe(); err != nil {
			logger().Fatalf("start %s listener failed: %v", s.udpServer.Net, err)
		}
	}()

	go func() {
		if err := s.tcpServer.ListenAndServe(); err != nil {
			logger().Fatalf("start %s listener failed: %v", s.tcpServer.Net, err)
		}
	}()

	go func() {
		if s.httpListener != nil {
			logger().Infof("http server is up and running on port %d", s.cfg.HTTPPort)

			if err := http.Serve(s.httpListener, s.httpMux); err != nil {
				logger().Fatalf("start http listener failed: %v", err)
			}
		}
	}()

	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGUSR1)

	go func() {
		for {
			<-signals
			s.printConfiguration()
		}
	}()
}

func (s *Server) Stop() {
	logger().Info("Stopping server")

	if err := s.udpServer.Shutdown(); err != nil {
		logger().Fatalf("stop %s listener failed: %v", s.udpServer.Net, err)
	}

	if err := s.tcpServer.Shutdown(); err != nil {
		logger().Fatalf("stop %s listener failed: %v", s.tcpServer.Net, err)
	}
}

func createResolverRequest(remoteAddress net.Addr, request *dns.Msg) *resolver.Request {
	clientIP := resolveClientIP(remoteAddress)

	return &resolver.Request{
		ClientIP:  clientIP,
		Req:       request,
		RequestTS: time.Now(),
		Log: logrus.WithFields(logrus.Fields{
			"question":  util.QuestionToString(request.Question),
			"client_ip": clientIP,
		}),
	}
}

func (s *Server) OnRequest(w dns.ResponseWriter, request *dns.Msg) {
	logger().Debug("new request")

	r := createResolverRequest(w.RemoteAddr(), request)

	response, err := s.queryResolver.Resolve(r)

	if err != nil {
		logger().Errorf("error on processing request: %v", err)
		dns.HandleFailed(w, request)
	} else {
		response.Res.MsgHdr.RecursionAvailable = request.MsgHdr.RecursionDesired

		if err := w.WriteMsg(response.Res); err != nil {
			logger().Error("can't write message: ", err)
		}
	}
}

// Handler for docker healthcheck. Just returns OK code without delegating to resolver chain
func (s *Server) OnHealthCheck(w dns.ResponseWriter, request *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(request)
	resp.Rcode = dns.RcodeSuccess

	if err := w.WriteMsg(resp); err != nil {
		logger().Error("can't write message: ", err)
	}
}

func (s *Server) registerAPIEndpoints(router *chi.Mux) {
	router.Post(api.BlockingQueryPath, s.apiQuery)
}

func resolveClientIP(addr net.Addr) net.IP {
	var clientIP net.IP
	if t, ok := addr.(*net.UDPAddr); ok {
		clientIP = t.IP
	} else if t, ok := addr.(*net.TCPAddr); ok {
		clientIP = t.IP
	}

	return clientIP
}
