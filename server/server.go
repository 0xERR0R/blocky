package server

import (
	"blocky/config"
	"blocky/metrics"
	"blocky/resolver"
	"net/http"
	"runtime"
	"runtime/debug"
	"time"

	"blocky/util"
	"fmt"
	"net"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

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
	return logrus.WithField("prefix", "server")
}

func NewServer(cfg *config.Config) (server *Server, err error) {
	udpServer := &dns.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Net:     "udp",
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			logger().Infof("udp server is up and running on port %d", cfg.Port)
		},
		UDPSize: 65535}
	tcpServer := &dns.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Net:     "tcp",
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			logger().Infof("tcp server is up and running on port %d", cfg.Port)
		},
	}

	var httpListener, httpsListener net.Listener

	router := createRouter(cfg)

	if cfg.HTTPPort > 0 {
		if httpListener, err = net.Listen("tcp", fmt.Sprintf(":%d", cfg.HTTPPort)); err != nil {
			return nil, fmt.Errorf("start http listener on port %d failed: %v", cfg.HTTPPort, err)
		}

		metrics.Start(router, cfg.Prometheus)
	}

	if cfg.HTTPSPort > 0 {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, fmt.Errorf("httpsCertFile and httpsKeyFile parameters are mandatory for HTTPS")
		}

		if httpsListener, err = net.Listen("tcp", fmt.Sprintf(":%d", cfg.HTTPSPort)); err != nil {
			return nil, fmt.Errorf("start https listener on port %d failed: %v", cfg.HTTPSPort, err)
		}

		metrics.Start(router, cfg.Prometheus)
	}

	queryResolver := createQueryResolver(cfg, router)

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

	return server, nil
}

func createQueryResolver(cfg *config.Config, router *chi.Mux) resolver.Resolver {
	return resolver.Chain(
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

	go func() {
		if s.httpsListener != nil {
			logger().Infof("https server is up and running on port %d", s.cfg.HTTPSPort)

			if err := http.ServeTLS(s.httpsListener, s.httpMux, s.cfg.CertFile, s.cfg.KeyFile); err != nil {
				logger().Fatalf("start https listener failed: %v", err)
			}
		}
	}()

	registerPrintConfigurationTrigger(s)
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
	clientIP, protocol := resolveClientIPAndProtocol(remoteAddress)

	return newRequest(clientIP, protocol, request)
}

func newRequest(clientIP net.IP, protocol resolver.RequestProtocol, request *dns.Msg) *resolver.Request {
	return &resolver.Request{
		ClientIP:  clientIP,
		Protocol:  protocol,
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

// Handler for docker health check. Just returns OK code without delegating to resolver chain
func (s *Server) OnHealthCheck(w dns.ResponseWriter, request *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(request)
	resp.Rcode = dns.RcodeSuccess

	if err := w.WriteMsg(resp); err != nil {
		logger().Error("can't write message: ", err)
	}
}

func resolveClientIPAndProtocol(addr net.Addr) (ip net.IP, protocol resolver.RequestProtocol) {
	if t, ok := addr.(*net.UDPAddr); ok {
		return t.IP, resolver.UDP
	} else if t, ok := addr.(*net.TCPAddr); ok {
		return t.IP, resolver.TCP
	}

	return nil, resolver.TCP
}
