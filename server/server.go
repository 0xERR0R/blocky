package server

import (
	"blocky/config"
	"blocky/resolver"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"

	"blocky/util"
	"fmt"
	"net"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Server struct {
	udpServer     *dns.Server
	tcpServer     *dns.Server
	queryResolver resolver.Resolver
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
			logger().Infof("udp server is up and running")
		},
		UDPSize: 65535}
	tcpServer := &dns.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Net:     "tcp",
		Handler: tcpHandler,
		NotifyStartedFunc: func() {
			logger().Infof("tcp server is up and running")
		},
	}

	metrics := resolver.NewMetricsResolver(cfg.Prometheus)
	queryResolver := resolver.Chain(
		resolver.NewClientNamesResolver(cfg.ClientLookup),
		resolver.NewQueryLoggingResolver(cfg.QueryLog),
		resolver.NewStatsResolver(),
		&metrics,
		resolver.NewConditionalUpstreamResolver(cfg.Conditional),
		resolver.NewCustomDNSResolver(cfg.CustomDNS),
		resolver.NewBlockingResolver(cfg.Blocking),
		resolver.NewCachingResolver(cfg.Caching),
		resolver.NewParallelBestResolver(cfg.Upstream),
	)

	server := Server{
		udpServer:     udpServer,
		tcpServer:     tcpServer,
		queryResolver: queryResolver,
	}

	server.printConfiguration()

	udpHandler.HandleFunc(".", server.OnRequest)
	udpHandler.HandleFunc("healthcheck.blocky", server.OnHealthCheck)
	tcpHandler.HandleFunc(".", server.OnRequest)
	tcpHandler.HandleFunc("healthcheck.blocky", server.OnHealthCheck)

	return &server, nil
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

func (s *Server) OnRequest(w dns.ResponseWriter, request *dns.Msg) {
	logger().Debug("new request")

	clientIP := resolveClientIP(w.RemoteAddr())
	r := &resolver.Request{
		ClientIP: clientIP,
		Req:      request,
		Log: logrus.WithFields(logrus.Fields{
			"question":  util.QuestionToString(request.Question),
			"client_ip": clientIP,
		}),
	}

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

func resolveClientIP(addr net.Addr) net.IP {
	var clientIP net.IP
	if t, ok := addr.(*net.UDPAddr); ok {
		clientIP = t.IP
	} else if t, ok := addr.(*net.TCPAddr); ok {
		clientIP = t.IP
	}

	return clientIP
}
