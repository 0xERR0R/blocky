package server

import (
	"fmt"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/resolver"
	"github.com/0xERR0R/blocky/util"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Server controls the endpoints for DNS and HTTP
type Server struct {
	udpServer     *dns.Server
	tcpServer     *dns.Server
	httpListener  net.Listener
	httpsListener net.Listener
	queryResolver resolver.Resolver
	cfg           *config.Config
	httpMux       *chi.Mux
}

func logger() *logrus.Entry {
	return log.PrefixedLog("server")
}

func getServerAddress(addr string) string {
	address := addr
	if !strings.Contains(addr, ":") {
		address = fmt.Sprintf(":%s", addr)
	}

	return address
}

// NewServer creates new server instance with passed config
func NewServer(cfg *config.Config) (server *Server, err error) {
	address := getServerAddress(cfg.Port)

	log.ConfigureLogger(cfg.LogLevel, cfg.LogFormat, cfg.LogTimestamp)

	udpServer := createUDPServer(address)
	tcpServer := createTCPServer(address)

	var httpListener, httpsListener net.Listener

	router := createRouter(cfg)

	if cfg.HTTPPort != "" {
		if httpListener, err = net.Listen("tcp", getServerAddress(cfg.HTTPPort)); err != nil {
			return nil, fmt.Errorf("start http listener on %s failed: %w", cfg.HTTPPort, err)
		}

		metrics.Start(router, cfg.Prometheus)
	}

	if cfg.HTTPSPort != "" {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, fmt.Errorf("httpsCertFile and httpsKeyFile parameters are mandatory for HTTPS")
		}

		if httpsListener, err = net.Listen("tcp", getServerAddress(cfg.HTTPSPort)); err != nil {
			return nil, fmt.Errorf("start https listener on port %s failed: %w", cfg.HTTPSPort, err)
		}

		metrics.Start(router, cfg.Prometheus)
	}

	metrics.RegisterEventListeners()

	queryResolver := createQueryResolver(cfg)
	server = &Server{
		udpServer:     udpServer,
		tcpServer:     tcpServer,
		queryResolver: queryResolver,
		cfg:           cfg,
		httpListener:  httpListener,
		httpsListener: httpsListener,
		httpMux:       router,
	}

	server.printConfiguration()

	server.registerDNSHandlers(udpServer)
	server.registerDNSHandlers(tcpServer)
	server.registerAPIEndpoints(router)

	registerResolverAPIEndpoints(router, queryResolver)

	return server, nil
}

func registerResolverAPIEndpoints(router chi.Router, res resolver.Resolver) {
	for res != nil {
		api.RegisterEndpoint(router, res)

		if cr, ok := res.(resolver.ChainedResolver); ok {
			res = cr.GetNext()
		} else {
			return
		}
	}
}

func createTCPServer(address string) *dns.Server {
	return &dns.Server{
		Addr:    address,
		Net:     "tcp",
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			logger().Infof("tcp server is up and running on address %s", address)
		},
	}
}

func createUDPServer(address string) *dns.Server {
	return &dns.Server{
		Addr:    address,
		Net:     "udp",
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			logger().Infof("udp server is up and running on address %s", address)
		},
		UDPSize: 65535}
}

func createQueryResolver(cfg *config.Config) resolver.Resolver {
	return resolver.Chain(
		resolver.NewIPv6Checker(cfg.DisableIPv6),
		resolver.NewClientNamesResolver(cfg.ClientLookup),
		resolver.NewQueryLoggingResolver(cfg.QueryLog),
		resolver.NewMetricsResolver(cfg.Prometheus),
		resolver.NewCustomDNSResolver(cfg.CustomDNS),
		resolver.NewBlockingResolver(cfg.Blocking),
		resolver.NewCachingResolver(cfg.Caching),
		resolver.NewConditionalUpstreamResolver(cfg.Conditional),
		resolver.NewParallelBestResolver(cfg.Upstream.ExternalResolvers),
	)
}

func (s *Server) registerDNSHandlers(server *dns.Server) {
	handler := server.Handler.(*dns.ServeMux)
	handler.HandleFunc(".", s.OnRequest)
	handler.HandleFunc("healthcheck.blocky", s.OnHealthCheck)
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

	logger().Infof("- DNS listening port: '%s'", s.cfg.Port)
	logger().Infof("- HTTP listening on addr/port: %s", s.cfg.HTTPPort)

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

// Start starts the server
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
			logger().Infof("http server is up and running on addr/port %s", s.cfg.HTTPPort)

			err := http.Serve(s.httpListener, s.httpMux)
			util.FatalOnError("start http listener failed: ", err)
		}
	}()

	go func() {
		if s.httpsListener != nil {
			logger().Infof("https server is up and running on addr/port %s", s.cfg.HTTPSPort)

			err := http.ServeTLS(s.httpsListener, s.httpMux, s.cfg.CertFile, s.cfg.KeyFile)
			util.FatalOnError("start https listener failed: ", err)
		}
	}()

	registerPrintConfigurationTrigger(s)
}

// Stop stops the server
func (s *Server) Stop() {
	logger().Info("Stopping server")

	if err := s.udpServer.Shutdown(); err != nil {
		logger().Fatalf("stop %s listener failed: %v", s.udpServer.Net, err)
	}

	if err := s.tcpServer.Shutdown(); err != nil {
		logger().Fatalf("stop %s listener failed: %v", s.tcpServer.Net, err)
	}
}

func createResolverRequest(remoteAddress net.Addr, request *dns.Msg) *model.Request {
	clientIP, protocol := resolveClientIPAndProtocol(remoteAddress)

	return newRequest(clientIP, protocol, request)
}

func newRequest(clientIP net.IP, protocol model.RequestProtocol, request *dns.Msg) *model.Request {
	return &model.Request{
		ClientIP:  clientIP,
		Protocol:  protocol,
		Req:       request,
		RequestTS: time.Now(),
		Log: log.Log().WithFields(logrus.Fields{
			"question":  util.QuestionToString(request.Question),
			"client_ip": clientIP,
		}),
	}
}

// OnRequest will be executed if a new DNS request is received
func (s *Server) OnRequest(w dns.ResponseWriter, request *dns.Msg) {
	logger().Debug("new request")

	r := createResolverRequest(w.RemoteAddr(), request)

	response, err := s.queryResolver.Resolve(r)

	if err != nil {
		logger().Errorf("error on processing request: %v", err)

		m := new(dns.Msg)
		m.SetRcode(request, dns.RcodeServerFailure)
		err := w.WriteMsg(m)
		util.LogOnError("can't write message: ", err)
	} else {
		response.Res.MsgHdr.RecursionAvailable = request.MsgHdr.RecursionDesired

		// truncate if necessary
		response.Res.Truncate(getMaxResponseSize(w.LocalAddr().Network(), request))

		// enable compression
		response.Res.Compress = true

		err := w.WriteMsg(response.Res)
		util.LogOnError("can't write message: ", err)
	}
}

// returns EDNS upd size or if not present, 512 for UDP and 64K for TCP
func getMaxResponseSize(network string, request *dns.Msg) int {
	edns := request.IsEdns0()
	if edns != nil && edns.UDPSize() > 0 {
		return int(edns.UDPSize())
	}

	if network == "tcp" {
		return dns.MaxMsgSize
	}

	return dns.MinMsgSize
}

// OnHealthCheck Handler for docker health check. Just returns OK code without delegating to resolver chain
func (s *Server) OnHealthCheck(w dns.ResponseWriter, request *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(request)
	resp.Rcode = dns.RcodeSuccess

	err := w.WriteMsg(resp)
	util.LogOnError("can't write message: ", err)
}

func resolveClientIPAndProtocol(addr net.Addr) (ip net.IP, protocol model.RequestProtocol) {
	if t, ok := addr.(*net.UDPAddr); ok {
		return t.IP, model.RequestProtocolUDP
	} else if t, ok := addr.(*net.TCPAddr); ok {
		return t.IP, model.RequestProtocolTCP
	}

	return nil, model.RequestProtocolUDP
}
