package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/redis"
	"github.com/0xERR0R/blocky/resolver"
	"github.com/0xERR0R/blocky/service"
	"golang.org/x/exp/maps"

	"github.com/0xERR0R/blocky/util"
	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"

	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	maxUDPBufferSize = 65535
	caExpiryYears    = 10
	certExpiryYears  = 5
)

// Server controls the endpoints for DNS and HTTP
type Server struct {
	dnsServers    []*dns.Server
	queryResolver resolver.ChainedResolver
	cfg           *config.Config

	services map[service.Listener]service.Service
}

type subServer interface {
	fmt.Stringer
	service.Service

	Serve(context.Context, net.Listener) error
}

func logger() *logrus.Entry {
	return log.PrefixedLog("server")
}

func tlsCipherSuites() []uint16 {
	tlsCipherSuites := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	return tlsCipherSuites
}

type NewServerFunc func(address string) (*dns.Server, error)

func retrieveCertificate(cfg *config.Config) (cert tls.Certificate, err error) {
	if cfg.CertFile == "" && cfg.KeyFile == "" {
		cert, err = util.TLSGenerateSelfSignedCert([]string{"blocky.invalid", "*"})
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("unable to generate self-signed certificate: %w", err)
		}

		log.Log().Info("using self-signed certificate")
	} else {
		cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("can't load certificate files: %w", err)
		}
	}

	return
}

func newTLSConfig(cfg *config.Config) (*tls.Config, error) {
	var cert tls.Certificate

	cert, err := retrieveCertificate(cfg)
	if err != nil {
		return nil, fmt.Errorf("can't retrieve cert: %w", err)
	}

	// #nosec G402 // See TLSVersion.validate
	res := &tls.Config{
		MinVersion:   uint16(cfg.MinTLSServeVer),
		CipherSuites: tlsCipherSuites(),
		Certificates: []tls.Certificate{cert},
	}

	return res, nil
}

// NewServer creates new server instance with passed config
//
//nolint:funlen
func NewServer(ctx context.Context, cfg *config.Config) (server *Server, err error) {
	cfg.CopyPortsToServices()

	var tlsCfg *tls.Config

	if len(cfg.Ports.HTTPS) > 0 || len(cfg.Ports.TLS) > 0 {
		tlsCfg, err = newTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
	}

	dnsServers, err := createServers(cfg, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("server creation failed: %w", err)
	}

	listeners, err := createListeners(ctx, cfg, tlsCfg)
	if err != nil {
		return nil, err
	}

	metrics.RegisterEventListeners()

	bootstrap, err := resolver.NewBootstrap(ctx, cfg)
	if err != nil {
		return nil, err
	}

	var redisClient *redis.Client
	if cfg.Redis.IsEnabled() {
		redisClient, err = redis.New(ctx, &cfg.Redis)
		if err != nil && cfg.Redis.Required {
			return nil, err
		}
	}

	queryResolver, queryError := createQueryResolver(ctx, cfg, bootstrap, redisClient)
	if queryError != nil {
		return nil, queryError
	}

	server = &Server{
		dnsServers:    dnsServers,
		queryResolver: queryResolver,
		cfg:           cfg,
	}

	server.printConfiguration()

	server.registerDNSHandlers(ctx)

	services, err := server.createServices()
	if err != nil {
		return nil, err
	}

	server.services, err = service.GroupByListener(services, listeners)
	if err != nil {
		return nil, err
	}

	return server, err
}

func (s *Server) createServices() ([]service.Service, error) {
	openAPIImpl, err := s.createOpenAPIInterfaceImpl()
	if err != nil {
		return nil, err
	}

	res := []service.Service{
		newHTTPMiscService(s.cfg, openAPIImpl),
		newDoHService(s.cfg.Services.DoH, s.handleReq),
	}

	// Remove services the user has not enabled
	res = slices.DeleteFunc(res, func(svc service.Service) bool {
		return len(svc.ExposeOn()) == 0
	})

	return res, nil
}

func createServers(cfg *config.Config, tlsCfg *tls.Config) ([]*dns.Server, error) {
	var dnsServers []*dns.Server

	var err *multierror.Error

	addServers := func(newServer NewServerFunc, addresses config.ListenConfig) error {
		for _, address := range addresses {
			server, err := newServer(address)
			if err != nil {
				return err
			}

			dnsServers = append(dnsServers, server)
		}

		return nil
	}

	err = multierror.Append(err,
		addServers(createUDPServer, cfg.Ports.DNS),
		addServers(createTCPServer, cfg.Ports.DNS),
		addServers(func(address string) (*dns.Server, error) {
			return createTLSServer(address, tlsCfg)
		}, cfg.Ports.TLS))

	return dnsServers, err.ErrorOrNil()
}

func createListeners(ctx context.Context, cfg *config.Config, tlsCfg *tls.Config) ([]service.Listener, error) {
	res := make(map[string]service.Listener)

	listenTLS := func(ctx context.Context, endpoint service.Endpoint) (service.Listener, error) {
		return service.ListenTLS(ctx, endpoint, tlsCfg)
	}

	err := errors.Join(
		newListeners(ctx, service.HTTPProtocol, cfg.Ports.HTTP, service.ListenTCP, res),
		newListeners(ctx, service.HTTPSProtocol, cfg.Ports.HTTPS, listenTLS, res),
		newListeners(ctx, service.HTTPProtocol, cfg.Services.DoH.Addrs.HTTP, service.ListenTCP, res),
		newListeners(ctx, service.HTTPSProtocol, cfg.Services.DoH.Addrs.HTTPS, listenTLS, res),
	)
	if err != nil {
		return nil, err
	}

	return maps.Values(res), nil
}

type listenFunc[T service.Listener] func(context.Context, service.Endpoint) (T, error)

func newListeners[T service.Listener](
	ctx context.Context, proto string, addrs config.ListenConfig, listen listenFunc[T], out map[string]service.Listener,
) error {
	for _, addr := range addrs {
		key := fmt.Sprintf("%s:%s", proto, addr)
		if _, ok := out[key]; ok {
			// Avoid "address already in use"
			// We instead try to merge services, see services.GroupByListener
			continue
		}

		endpoint := service.Endpoint{
			Protocol: proto,
			AddrConf: addr,
		}

		l, err := listen(ctx, endpoint)
		if err != nil {
			return err // already has all info
		}

		out[key] = l
	}

	return nil
}

func createTLSServer(address string, tlsCfg *tls.Config) (*dns.Server, error) {
	return &dns.Server{
		Addr:      address,
		Net:       "tcp-tls",
		TLSConfig: tlsCfg,
		Handler:   dns.NewServeMux(),
		NotifyStartedFunc: func() {
			logger().Infof("TLS server is up and running on address %s", address)
		},
	}, nil
}

func createTCPServer(address string) (*dns.Server, error) {
	return &dns.Server{
		Addr:    address,
		Net:     "tcp",
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			logger().Infof("TCP server is up and running on address %s", address)
		},
	}, nil
}

func createUDPServer(address string) (*dns.Server, error) {
	return &dns.Server{
		Addr:    address,
		Net:     "udp",
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			logger().Infof("UDP server is up and running on address %s", address)
		},
		UDPSize: maxUDPBufferSize,
	}, nil
}

func createQueryResolver(
	ctx context.Context,
	cfg *config.Config,
	bootstrap *resolver.Bootstrap,
	redisClient *redis.Client,
) (resolver.ChainedResolver, error) {
	upstreamTree, utErr := resolver.NewUpstreamTreeResolver(ctx, cfg.Upstreams, bootstrap)
	blocking, blErr := resolver.NewBlockingResolver(ctx, cfg.Blocking, redisClient, bootstrap)
	clientNames, cnErr := resolver.NewClientNamesResolver(ctx, cfg.ClientLookup, cfg.Upstreams, bootstrap)
	queryLogging, qlErr := resolver.NewQueryLoggingResolver(ctx, cfg.QueryLog)
	condUpstream, cuErr := resolver.NewConditionalUpstreamResolver(ctx, cfg.Conditional, cfg.Upstreams, bootstrap)
	hostsFile, hfErr := resolver.NewHostsFileResolver(ctx, cfg.HostsFile, bootstrap)

	err := multierror.Append(
		multierror.Prefix(utErr, "upstream tree resolver: "),
		multierror.Prefix(blErr, "blocking resolver: "),
		multierror.Prefix(qlErr, "query logging resolver: "),
		multierror.Prefix(cnErr, "client names resolver: "),
		multierror.Prefix(cuErr, "conditional upstream resolver: "),
		multierror.Prefix(hfErr, "hosts file resolver: "),
	).ErrorOrNil()
	if err != nil {
		return nil, err
	}

	r := resolver.Chain(
		resolver.NewFilteringResolver(cfg.Filtering),
		resolver.NewFQDNOnlyResolver(cfg.FQDNOnly),
		resolver.NewECSResolver(cfg.ECS),
		clientNames,
		resolver.NewEDEResolver(cfg.EDE),
		queryLogging,
		resolver.NewMetricsResolver(cfg.Prometheus),
		resolver.NewRewriterResolver(cfg.CustomDNS.RewriterConfig, resolver.NewCustomDNSResolver(cfg.CustomDNS)),
		hostsFile,
		blocking,
		resolver.NewCachingResolver(ctx, cfg.Caching, redisClient),
		resolver.NewRewriterResolver(cfg.Conditional.RewriterConfig, condUpstream),
		resolver.NewSpecialUseDomainNamesResolver(cfg.SUDN),
		upstreamTree,
	)

	return r, nil
}

func (s *Server) registerDNSHandlers(ctx context.Context) {
	for _, server := range s.dnsServers {
		handler := server.Handler.(*dns.ServeMux)
		handler.HandleFunc(".", func(w dns.ResponseWriter, m *dns.Msg) {
			s.OnRequest(ctx, w, m)
		})
		handler.HandleFunc("healthcheck.blocky", func(w dns.ResponseWriter, m *dns.Msg) {
			s.OnHealthCheck(ctx, w, m)
		})
	}
}

func (s *Server) printConfiguration() {
	logger().Info("current configuration:")

	if s.cfg.Redis.IsEnabled() {
		logger().Info("Redis:")
		log.WithIndent(logger(), "  ", s.cfg.Redis.LogConfig)
	}

	resolver.ForEach(s.queryResolver, func(res resolver.Resolver) {
		resolver.LogResolverConfig(res, logger())
	})

	logger().Info("listeners:")
	log.WithIndent(logger(), "  ", s.cfg.Ports.LogConfig)

	logger().Info("runtime information:")

	// force garbage collector
	runtime.GC()
	debug.FreeOSMemory()

	logger().Infof("  numCPU =       %d", runtime.NumCPU())
	logger().Infof("  numGoroutine = %d", runtime.NumGoroutine())

	// gather memory stats
	var m runtime.MemStats

	runtime.ReadMemStats(&m)

	logger().Infof("  memory:")
	logger().Infof("    heap =     %10v MB", toMB(m.HeapAlloc))
	logger().Infof("    sys =      %10v MB", toMB(m.Sys))
	logger().Infof("    numGC =    %10v", m.NumGC)
}

func toMB(b uint64) uint64 {
	const bytesInKB = 1024

	return b / bytesInKB / bytesInKB
}

func newSubServer(svc service.Service) (subServer, error) {
	switch svc := svc.(type) {
	case service.HTTPService:
		return newHTTPServer(svc), nil

	default:
		return nil, fmt.Errorf("unsupported service type: %T (%s)", svc, svc)
	}
}

// Start starts the server
func (s *Server) Start(ctx context.Context, errCh chan<- error) {
	logger().Info("Starting server")

	for _, srv := range s.dnsServers {
		srv := srv

		go func() {
			if err := srv.ListenAndServe(); err != nil {
				errCh <- fmt.Errorf("start %s listener failed: %w", srv.Net, err)
			}
		}()
	}

	for listener, svc := range s.services {
		listener, svc := listener, svc

		srv, err := newSubServer(svc)
		if err != nil {
			errCh <- fmt.Errorf("%s on %s: %w", svc.ServiceName(), listener.Exposes(), err)

			return
		}

		go func() {
			logger().Infof("%s server is up and running on %s", svc.ServiceName(), listener.Exposes())

			err := srv.Serve(ctx, listener)
			if err != nil {
				errCh <- fmt.Errorf("%s on %s: %w", srv, listener.Addr(), err)
			}
		}()
	}

	registerPrintConfigurationTrigger(ctx, s)
}

// Stop stops the server
func (s *Server) Stop(ctx context.Context) error {
	logger().Info("Stopping server")

	for _, server := range s.dnsServers {
		if err := server.ShutdownContext(ctx); err != nil {
			return fmt.Errorf("stop %s listener failed: %w", server.Net, err)
		}
	}

	return nil
}

func extractClientIDFromHost(hostName string) string {
	const clientIDPrefix = "id-"
	if strings.HasPrefix(hostName, clientIDPrefix) && strings.Contains(hostName, ".") {
		return hostName[len(clientIDPrefix):strings.Index(hostName, ".")]
	}

	return ""
}

func newRequest(
	ctx context.Context,
	clientIP net.IP, clientID string,
	protocol model.RequestProtocol, request *dns.Msg,
) (context.Context, *model.Request) {
	ctx, logger := log.CtxWithFields(ctx, logrus.Fields{
		"req_id":    uuid.New().String(),
		"question":  util.QuestionToString(request.Question),
		"client_ip": clientIP,
	})

	logger.WithFields(logrus.Fields{
		"client_request_id": request.Id,
		"client_id":         clientID,
		"protocol":          protocol,
	}).Trace("new incoming request")

	req := model.Request{
		ClientIP:        clientIP,
		RequestClientID: clientID,
		Protocol:        protocol,
		Req:             request,
		RequestTS:       time.Now(),
	}

	return ctx, &req
}

func newRequestFromDNS(ctx context.Context, rw dns.ResponseWriter, msg *dns.Msg) (context.Context, *model.Request) {
	var (
		clientIP net.IP
		protocol model.RequestProtocol
	)

	if rw != nil {
		clientIP, protocol = resolveClientIPAndProtocol(rw.RemoteAddr())
	}

	var clientID string
	if con, ok := rw.(dns.ConnectionStater); ok && con.ConnectionState() != nil {
		clientID = extractClientIDFromHost(con.ConnectionState().ServerName)
	}

	return newRequest(ctx, clientIP, clientID, protocol, msg)
}

func newRequestFromHTTP(ctx context.Context, req *http.Request, msg *dns.Msg) (context.Context, *model.Request) {
	protocol := model.RequestProtocolTCP
	clientIP := util.HTTPClientIP(req)

	clientID := chi.URLParam(req, "clientID")
	if clientID == "" {
		clientID = extractClientIDFromHost(req.Host)
	}

	return newRequest(ctx, clientIP, clientID, protocol, msg)
}

// OnRequest will be executed if a new DNS request is received
func (s *Server) OnRequest(ctx context.Context, w dns.ResponseWriter, msg *dns.Msg) {
	ctx, request := newRequestFromDNS(ctx, w, msg)

	s.handleReq(ctx, request, w)
}

type msgWriter interface {
	WriteMsg(msg *dns.Msg) error
}

type dnsHandler func(context.Context, *model.Request, msgWriter)

func (s *Server) handleReq(ctx context.Context, request *model.Request, w msgWriter) {
	response, err := s.resolve(ctx, request)
	if err != nil {
		log.FromCtx(ctx).Error("error on processing request:", err)

		m := new(dns.Msg)
		m.SetRcode(request.Req, dns.RcodeServerFailure)
		err := w.WriteMsg(m)
		util.LogOnError(ctx, "can't write message: ", err)
	} else {
		err := w.WriteMsg(response.Res)
		util.LogOnError(ctx, "can't write message: ", err)
	}
}

func (s *Server) resolve(ctx context.Context, request *model.Request) (response *model.Response, rerr error) {
	defer func() {
		if val := recover(); val != nil {
			rerr = fmt.Errorf("panic occurred: %v", val)
		}
	}()

	contextUpstreamTimeoutMultiplier := 100
	timeoutDuration := time.Duration(contextUpstreamTimeoutMultiplier) * s.cfg.Upstreams.Timeout.ToDuration()

	ctx, cancel := context.WithTimeout(ctx, timeoutDuration)

	defer cancel()

	switch {
	case len(request.Req.Question) == 0:
		m := new(dns.Msg)
		m.SetRcode(request.Req, dns.RcodeFormatError)

		log.FromCtx(ctx).Error("query has no questions")

		response = &model.Response{Res: m, RType: model.ResponseTypeCUSTOMDNS, Reason: "CUSTOM DNS"}
	default:
		var err error

		response, err = s.queryResolver.Resolve(ctx, request)
		if err != nil {
			var upstreamErr *resolver.UpstreamServerError

			if errors.As(err, &upstreamErr) {
				response = &model.Response{Res: upstreamErr.Msg, RType: model.ResponseTypeRESOLVED, Reason: upstreamErr.Error()}
			} else {
				return nil, err
			}
		}
	}

	response.Res.MsgHdr.RecursionAvailable = request.Req.MsgHdr.RecursionDesired

	// truncate if necessary
	response.Res.Truncate(getMaxResponseSize(request))

	// enable compression
	response.Res.Compress = true

	return response, nil
}

// returns EDNS UDP size or if not present, 512 for UDP and 64K for TCP
func getMaxResponseSize(req *model.Request) int {
	edns := req.Req.IsEdns0()
	if edns != nil && edns.UDPSize() > 0 {
		return int(edns.UDPSize())
	}

	if req.Protocol == model.RequestProtocolTCP {
		return dns.MaxMsgSize
	}

	return dns.MinMsgSize
}

// OnHealthCheck Handler for docker health check. Just returns OK code without delegating to resolver chain
func (s *Server) OnHealthCheck(ctx context.Context, w dns.ResponseWriter, request *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(request)
	resp.Rcode = dns.RcodeSuccess

	err := w.WriteMsg(resp)
	util.LogOnError(ctx, "can't write message: ", err)
}

func resolveClientIPAndProtocol(addr net.Addr) (ip net.IP, protocol model.RequestProtocol) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP, model.RequestProtocolUDP
	case *net.TCPAddr:
		return a.IP, model.RequestProtocolTCP
	}

	return nil, model.RequestProtocolUDP
}
