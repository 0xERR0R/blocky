package server

import (
	"crypto/tls"
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
	"github.com/0xERR0R/blocky/redis"
	"github.com/0xERR0R/blocky/resolver"
	"github.com/0xERR0R/blocky/util"

	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Server controls the endpoints for DNS and HTTP
type Server struct {
	dnsServers     []*dns.Server
	httpListeners  []net.Listener
	httpsListeners []net.Listener
	queryResolver  resolver.Resolver
	cfg            *config.Config
	httpMux        *chi.Mux
}

func logger() *logrus.Entry {
	return log.PrefixedLog("server")
}

func getServerAddress(addr string) string {
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf(":%s", addr)
	}

	return addr
}

type NewServerFunc func(address string) *dns.Server

// NewServer creates new server instance with passed config
func NewServer(cfg *config.Config) (server *Server, err error) {
	var dnsServers []*dns.Server

	log.ConfigureLogger(cfg.LogLevel, cfg.LogFormat, cfg.LogTimestamp)

	addServers := func(newServer NewServerFunc, addresses config.ListenConfig) {
		for _, address := range addresses {
			dnsServers = append(dnsServers, newServer(getServerAddress(address)))
		}
	}

	addServers(createUDPServer, cfg.DNSPorts)
	addServers(createTCPServer, cfg.DNSPorts)

	addServers(func(address string) *dns.Server {
		return createTLSServer(address, cfg.CertFile, cfg.KeyFile)
	}, cfg.TLSPorts)

	router := createRouter(cfg)

	httpListeners, httpsListeners, err := createHTTPListeners(cfg)
	if err != nil {
		return nil, err
	}

	if len(httpListeners) != 0 || len(httpsListeners) != 0 {
		metrics.Start(router, cfg.Prometheus)
	}

	metrics.RegisterEventListeners()

	redisClient, redisErr := redis.New(&cfg.Redis)
	if redisErr != nil && cfg.Redis.Required {
		return nil, redisErr
	}

	queryResolver, queryError := createQueryResolver(cfg, redisClient)
	if queryError != nil {
		return nil, queryError
	}

	server = &Server{
		dnsServers:     dnsServers,
		queryResolver:  queryResolver,
		cfg:            cfg,
		httpListeners:  httpListeners,
		httpsListeners: httpsListeners,
		httpMux:        router,
	}

	server.printConfiguration()

	server.registerDNSHandlers()
	server.registerAPIEndpoints(router)

	registerResolverAPIEndpoints(router, queryResolver)

	return server, err
}

func createHTTPListeners(cfg *config.Config) (httpListeners []net.Listener, httpsListeners []net.Listener, err error) {
	httpListeners, err = newListeners("http", cfg.HTTPPorts)
	if err != nil {
		return nil, nil, err
	}

	httpsListeners, err = newListeners("https", cfg.HTTPSPorts)
	if err != nil {
		return nil, nil, err
	}

	return httpListeners, httpsListeners, nil
}

func newListeners(proto string, addresses config.ListenConfig) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, len(addresses))

	for _, address := range addresses {
		listener, err := net.Listen("tcp", getServerAddress(address))
		if err != nil {
			return nil, fmt.Errorf("start %s listener on %s failed: %w", proto, address, err)
		}

		listeners = append(listeners, listener)
	}

	return listeners, nil
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

func createTLSServer(address string, certFile string, keyFile string) *dns.Server {
	cer, err := tls.LoadX509KeyPair(certFile, keyFile)
	util.FatalOnError("can't load certificate files: ", err)

	return &dns.Server{
		Addr: address,
		Net:  "tcp-tls",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		},
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			logger().Infof("TLS server is up and running on address %s", address)
		},
	}
}

func createTCPServer(address string) *dns.Server {
	return &dns.Server{
		Addr:    address,
		Net:     "tcp",
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			logger().Infof("TCP server is up and running on address %s", address)
		},
	}
}

func createUDPServer(address string) *dns.Server {
	return &dns.Server{
		Addr:    address,
		Net:     "udp",
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			logger().Infof("UDP server is up and running on address %s", address)
		},
		UDPSize: 65535}
}

func createQueryResolver(cfg *config.Config, redisClient *redis.Client) (resolver.Resolver, error) {
	br, brErr := resolver.NewBlockingResolver(cfg.Blocking, redisClient)

	return resolver.Chain(
		resolver.NewIPv6Checker(cfg.DisableIPv6),
		resolver.NewClientNamesResolver(cfg.ClientLookup),
		resolver.NewQueryLoggingResolver(cfg.QueryLog),
		resolver.NewMetricsResolver(cfg.Prometheus),
		resolver.NewCustomDNSResolver(cfg.CustomDNS),
		resolver.NewHostsFileResolver(cfg.HostsFile),
		br,
		resolver.NewCachingResolver(cfg.Caching, redisClient),
		resolver.NewConditionalUpstreamResolver(cfg.Conditional),
		resolver.NewParallelBestResolver(cfg.Upstream.ExternalResolvers),
	), brErr
}

func (s *Server) registerDNSHandlers() {
	for _, server := range s.dnsServers {
		handler := server.Handler.(*dns.ServeMux)
		handler.HandleFunc(".", s.OnRequest)
		handler.HandleFunc("healthcheck.blocky", s.OnHealthCheck)
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

	logger().Infof("- DNS listening on addrs/ports: %v", s.cfg.DNSPorts)
	logger().Infof("- TLS listening on addrs/ports: %v", s.cfg.TLSPorts)
	logger().Infof("- HTTP listening on addrs/ports: %v", s.cfg.HTTPPorts)
	logger().Infof("- HTTPS listening on addrs/ports: %v", s.cfg.HTTPSPorts)

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

	for _, srv := range s.dnsServers {
		srv := srv

		go func() {
			if err := srv.ListenAndServe(); err != nil {
				logger().Fatalf("start %s listener failed: %v", srv.Net, err)
			}
		}()
	}

	for i, listener := range s.httpListeners {
		listener := listener
		address := s.cfg.HTTPPorts[i]

		go func() {
			logger().Infof("http server is up and running on addr/port %s", address)

			err := http.Serve(listener, s.httpMux)
			util.FatalOnError("start http listener failed: ", err)
		}()
	}

	for i, listener := range s.httpsListeners {
		listener := listener
		address := s.cfg.HTTPSPorts[i]

		go func() {
			logger().Infof("https server is up and running on addr/port %s", address)

			err := http.ServeTLS(listener, s.httpMux, s.cfg.CertFile, s.cfg.KeyFile)
			util.FatalOnError("start https listener failed: ", err)
		}()
	}

	registerPrintConfigurationTrigger(s)
}

// Stop stops the server
func (s *Server) Stop() {
	logger().Info("Stopping server")

	for _, server := range s.dnsServers {
		if err := server.Shutdown(); err != nil {
			logger().Fatalf("stop %s listener failed: %v", server.Net, err)
		}
	}
}

func createResolverRequest(rw dns.ResponseWriter, request *dns.Msg) *model.Request {
	var hostName string

	var remoteAddr net.Addr

	if rw != nil {
		remoteAddr = rw.RemoteAddr()
	}

	clientIP, protocol := resolveClientIPAndProtocol(remoteAddr)
	con, ok := rw.(dns.ConnectionStater)

	if ok && con.ConnectionState() != nil {
		hostName = con.ConnectionState().ServerName
	}

	return newRequest(clientIP, protocol, extractClientIDFromHost(hostName), request)
}

func extractClientIDFromHost(hostName string) string {
	const clientIDPrefix = "id-"
	if strings.HasPrefix(hostName, clientIDPrefix) && strings.Contains(hostName, ".") {
		return hostName[len(clientIDPrefix):strings.Index(hostName, ".")]
	}

	return ""
}

func newRequest(clientIP net.IP, protocol model.RequestProtocol,
	requestClientID string, request *dns.Msg) *model.Request {
	return &model.Request{
		ClientIP:        clientIP,
		RequestClientID: requestClientID,
		Protocol:        protocol,
		Req:             request,
		Log: log.Log().WithFields(logrus.Fields{
			"question":  util.QuestionToString(request.Question),
			"client_ip": clientIP,
		}),
		RequestTS: time.Now(),
	}
}

// OnRequest will be executed if a new DNS request is received
func (s *Server) OnRequest(w dns.ResponseWriter, request *dns.Msg) {
	logger().Debug("new request")

	r := createResolverRequest(w, request)

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
