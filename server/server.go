package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/redis"
	"github.com/0xERR0R/blocky/resolver"

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

// chainedResolverHolder wraps a ChainedResolver so that atomic.Value always stores
// the same concrete type regardless of which ChainedResolver implementation is stored.
type chainedResolverHolder struct {
	r resolver.ChainedResolver
}

// Server controls the endpoints for DNS and HTTP
type Server struct {
	dnsServers    []*dns.Server
	queryResolver atomic.Value // stores chainedResolverHolder
	cfg           atomic.Pointer[config.Config]

	rootCtx        context.Context //nolint:containedctx // needed to derive resolver contexts on reload
	certProvider   *CertProvider
	servers        map[net.Listener]*httpServer
	configPath     string
	reloadMu       sync.Mutex
	resolverCancel context.CancelFunc
	bootstrap      *resolver.Bootstrap
	redisClient    *redis.Client
}

func (s *Server) getQueryResolver() resolver.ChainedResolver {
	return s.queryResolver.Load().(chainedResolverHolder).r
}

// Reload loads the configuration from disk and atomically swaps the resolver chain.
// Concurrent reload attempts are rejected.
func (s *Server) Reload() error {
	if !s.reloadMu.TryLock() {
		logger().Warn("config reload already in progress, skipping")

		return errors.New("reload already in progress")
	}
	defer s.reloadMu.Unlock()

	logger().Info("reloading configuration...")

	oldCfg := s.cfg.Load()

	newCfg, err := s.loadAndValidateConfig(oldCfg)
	if err != nil {
		return err
	}

	resolverCtx, resolverCancel := context.WithCancel(s.rootCtx)

	bootstrap, err := s.reloadBootstrap(resolverCtx, oldCfg, newCfg)
	if err != nil {
		resolverCancel()

		return err
	}

	opts := queryResolverOptions{
		blockingOpts: resolver.BlockingResolverOptions{IsReload: true},
	}

	newQueryResolver, err := createQueryResolver(resolverCtx, newCfg, bootstrap, s.redisClient, opts)
	if err != nil {
		resolverCancel()
		logger().Errorf("config reload failed: %v", err)
		metrics.ConfigReloadTotal.WithLabelValues("failed").Inc()

		return fmt.Errorf("config reload failed: %w", err)
	}

	s.applyReload(newCfg, newQueryResolver, bootstrap, resolverCancel, oldCfg)

	log.Configure(&newCfg.Log)
	s.printConfiguration()
	logger().Info("configuration reloaded successfully")
	metrics.ConfigReloadTotal.WithLabelValues("success").Inc()
	metrics.ConfigReloadTimestamp.SetToCurrentTime()

	return nil
}

func (s *Server) loadAndValidateConfig(oldCfg *config.Config) (*config.Config, error) {
	newCfg, err := config.LoadConfig(s.configPath, true)
	if err != nil {
		logger().Errorf("config reload failed: %v", err)
		metrics.ConfigReloadTotal.WithLabelValues("failed").Inc()

		return nil, fmt.Errorf("config reload failed: %w", err)
	}

	if !reflect.DeepEqual(oldCfg.Ports, newCfg.Ports) {
		logger().Warn("config reload: ports changed, restart required to apply")
	}

	if !reflect.DeepEqual(oldCfg.Redis, newCfg.Redis) {
		logger().Warn("config reload: redis changed, restart required to apply")
	}

	return newCfg, nil
}

func (s *Server) reloadBootstrap(
	resolverCtx context.Context,
	oldCfg, newCfg *config.Config,
) (*resolver.Bootstrap, error) {
	if reflect.DeepEqual(oldCfg.BootstrapDNS, newCfg.BootstrapDNS) {
		return s.bootstrap, nil
	}

	bootstrap, err := resolver.NewBootstrap(resolverCtx, newCfg)
	if err != nil {
		metrics.ConfigReloadTotal.WithLabelValues("failed").Inc()

		return nil, fmt.Errorf("config reload failed (bootstrap): %w", err)
	}

	return bootstrap, nil
}

func (s *Server) applyReload(
	newCfg *config.Config,
	newQueryResolver resolver.ChainedResolver,
	bootstrap *resolver.Bootstrap,
	resolverCancel context.CancelFunc,
	oldCfg *config.Config,
) {
	s.storeQueryResolver(newQueryResolver)
	s.cfg.Store(newCfg)

	if s.certProvider != nil && (oldCfg.CertFile != newCfg.CertFile || oldCfg.KeyFile != newCfg.KeyFile) {
		s.certProvider.UpdatePaths(newCfg.CertFile, newCfg.KeyFile)
	}

	oldCancel := s.resolverCancel
	s.resolverCancel = resolverCancel
	s.bootstrap = bootstrap

	// Allow in-flight requests on the old resolver chain to complete before
	// cancelling its context. The new chain is already serving new requests.
	go func() {
		time.Sleep(5 * time.Second)
		oldCancel()
	}()
}

// ActiveConfig returns the currently active configuration.
func (s *Server) ActiveConfig() *config.Config {
	return s.cfg.Load()
}

func (s *Server) storeQueryResolver(r resolver.ChainedResolver) {
	s.queryResolver.Store(chainedResolverHolder{r})
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

func newTLSConfig(ctx context.Context, cfg *config.Config) (*tls.Config, *CertProvider, error) {
	if cfg.CertFile == "" && cfg.KeyFile == "" {
		cert, err := util.TLSGenerateSelfSignedCert([]string{"blocky.invalid", "*"})
		if err != nil {
			return nil, nil, fmt.Errorf("unable to generate self-signed certificate: %w", err)
		}

		log.Log().Info("using self-signed certificate")

		// #nosec G402 // See TLSVersion.validate
		return &tls.Config{
			MinVersion:   uint16(cfg.MinTLSServeVer),
			CipherSuites: tlsCipherSuites(),
			Certificates: []tls.Certificate{cert},
		}, nil, nil
	}

	provider, err := NewCertProvider(ctx, cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("can't load certificate files: %w", err)
	}

	// #nosec G402 // See TLSVersion.validate
	return &tls.Config{
		MinVersion:     uint16(cfg.MinTLSServeVer),
		CipherSuites:   tlsCipherSuites(),
		GetCertificate: provider.GetCertificate,
	}, provider, nil
}

// NewServer creates new server instance with passed config.
// configPath is stored so that Reload() can re-read the configuration from disk.
//
//nolint:funlen
func NewServer(ctx context.Context, cfg *config.Config, configPath string) (server *Server, err error) {
	var (
		tlsCfg       *tls.Config
		certProvider *CertProvider
	)

	if len(cfg.Ports.HTTPS) > 0 || len(cfg.Ports.TLS) > 0 {
		tlsCfg, certProvider, err = newTLSConfig(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS configuration: %w", err)
		}
	}

	dnsServers, err := createServers(cfg, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("server creation failed: %w", err)
	}

	httpListeners, httpsListeners, err := createHTTPListeners(ctx, cfg, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP/HTTPS listeners: %w", err)
	}

	metrics.RegisterEventListeners()

	bootstrap, err := resolver.NewBootstrap(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create bootstrap resolver: %w", err)
	}

	var redisClient *redis.Client
	if cfg.Redis.IsEnabled() {
		redisClient, err = redis.New(ctx, &cfg.Redis)
		if err != nil && cfg.Redis.Required {
			return nil, fmt.Errorf("failed to create required Redis client: %w", err)
		}
	}

	resolverCtx, resolverCancel := context.WithCancel(ctx)

	queryResolver, queryError := createQueryResolver(resolverCtx, cfg, bootstrap, redisClient, queryResolverOptions{})
	if queryError != nil {
		resolverCancel()

		return nil, queryError
	}

	server = &Server{
		dnsServers:     dnsServers,
		rootCtx:        ctx,
		certProvider:   certProvider,
		servers:        make(map[net.Listener]*httpServer),
		configPath:     configPath,
		resolverCancel: resolverCancel,
		bootstrap:      bootstrap,
		redisClient:    redisClient,
	}
	server.storeQueryResolver(queryResolver)
	server.cfg.Store(cfg)

	server.printConfiguration()

	server.registerDNSHandlers(ctx)

	openAPIImpl, err := server.createOpenAPIInterfaceImpl()
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenAPI interface implementation: %w", err)
	}

	httpRouter := createHTTPRouter(cfg, openAPIImpl)
	server.registerDoHEndpoints(httpRouter, cfg)

	if len(cfg.Ports.HTTP) != 0 {
		srv := newHTTPServer("http", httpRouter, cfg)

		for _, l := range httpListeners {
			server.servers[l] = srv
		}
	}

	if len(cfg.Ports.HTTPS) != 0 {
		srv := newHTTPServer("https", httpRouter, cfg)

		for _, l := range httpsListeners {
			server.servers[l] = srv
		}
	}

	return server, err
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

	if multiErr := err.ErrorOrNil(); multiErr != nil {
		return nil, fmt.Errorf("failed to create DNS servers: %w", multiErr)
	}

	return dnsServers, nil
}

func createHTTPListeners(
	ctx context.Context, cfg *config.Config, tlsCfg *tls.Config,
) (httpListeners, httpsListeners []net.Listener, err error) {
	httpListeners, err = newTCPListeners(ctx, "http", cfg.Ports.HTTP)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HTTP listeners: %w", err)
	}

	httpsListeners, err = newTLSListeners(ctx, "https", cfg.Ports.HTTPS, tlsCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HTTPS listeners: %w", err)
	}

	return httpListeners, httpsListeners, nil
}

func newTCPListeners(
	ctx context.Context, proto string, addresses config.ListenConfig,
) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, len(addresses))
	lc := &net.ListenConfig{}

	for _, address := range addresses {
		listener, err := lc.Listen(ctx, "tcp", address)
		if err != nil {
			return nil, fmt.Errorf("start %s listener on %s failed: %w", proto, address, err)
		}

		listeners = append(listeners, listener)
	}

	return listeners, nil
}

func newTLSListeners(
	ctx context.Context, proto string, addresses config.ListenConfig, tlsCfg *tls.Config,
) ([]net.Listener, error) {
	listeners, err := newTCPListeners(ctx, proto, addresses)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP listeners for TLS: %w", err)
	}

	for i, inner := range listeners {
		listeners[i] = tls.NewListener(inner, tlsCfg)
	}

	return listeners, nil
}

func createDNSServer(network, address string, tlsCfg *tls.Config) (*dns.Server, error) {
	srv := &dns.Server{
		Addr:    address,
		Net:     network,
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			logger().Infof("%s server is up and running on address %s", strings.ToUpper(network), address)
		},
	}

	if network == "udp" {
		srv.UDPSize = maxUDPBufferSize
	}

	if tlsCfg != nil {
		srv.TLSConfig = tlsCfg
	}

	return srv, nil
}

func createTLSServer(address string, tlsCfg *tls.Config) (*dns.Server, error) {
	return createDNSServer("tcp-tls", address, tlsCfg)
}

func createTCPServer(address string) (*dns.Server, error) {
	return createDNSServer("tcp", address, nil)
}

func createUDPServer(address string) (*dns.Server, error) {
	return createDNSServer("udp", address, nil)
}

// queryResolverOptions holds optional parameters for createQueryResolver.
type queryResolverOptions struct {
	blockingOpts resolver.BlockingResolverOptions
}

func createQueryResolver(
	ctx context.Context,
	cfg *config.Config,
	bootstrap *resolver.Bootstrap,
	redisClient *redis.Client,
	opts queryResolverOptions,
) (resolver.ChainedResolver, error) {
	upstreamTree, utErr := resolver.NewUpstreamTreeResolver(ctx, cfg.Upstreams, bootstrap)
	blocking, blErr := resolver.NewBlockingResolverWithOptions(ctx, cfg.Blocking, redisClient, bootstrap,
		opts.blockingOpts)
	clientNames, cnErr := resolver.NewClientNamesResolver(ctx, cfg.ClientLookup, cfg.Upstreams, bootstrap)
	queryLogging, qlErr := resolver.NewQueryLoggingResolver(ctx, cfg.QueryLog)
	condUpstream, cuErr := resolver.NewConditionalUpstreamResolver(ctx, cfg.Conditional, cfg.Upstreams, bootstrap)
	hostsFile, hfErr := resolver.NewHostsFileResolver(ctx, cfg.HostsFile, bootstrap)
	cachingResolver, crErr := resolver.NewCachingResolver(ctx, cfg.Caching, redisClient)
	// Pass upstreamTree to DNSSEC resolver so it can query for DNSKEY/DS records
	dnssecResolver, dsErr := resolver.NewDNSSECResolver(ctx, cfg.DNSSEC, upstreamTree)

	multiErr := multierror.Append(
		multierror.Prefix(utErr, "upstream tree resolver: "),
		multierror.Prefix(blErr, "blocking resolver: "),
		multierror.Prefix(qlErr, "query logging resolver: "),
		multierror.Prefix(cnErr, "client names resolver: "),
		multierror.Prefix(cuErr, "conditional upstream resolver: "),
		multierror.Prefix(hfErr, "hosts file resolver: "),
		multierror.Prefix(crErr, "caching resolver: "),
		multierror.Prefix(dsErr, "dnssec resolver: "),
	).ErrorOrNil()
	if multiErr != nil {
		return nil, fmt.Errorf("failed to create query resolver components: %w", multiErr)
	}

	r := resolver.Chain(
		resolver.NewFilteringResolver(cfg.Filtering),
		resolver.NewFQDNOnlyResolver(cfg.FQDNOnly),
		clientNames,
		resolver.NewEDEResolver(cfg.EDE),
		queryLogging,
		resolver.NewMetricsResolver(cfg.Prometheus),
		resolver.NewCustomDNSResolver(cfg.CustomDNS),
		hostsFile,
		blocking,
		dnssecResolver, // DNSSEC validation BEFORE caching - validates all responses before they are cached
		cachingResolver,
		resolver.NewDNS64Resolver(cfg.DNS64), // DNS64 synthesis AFTER caching
		resolver.NewECSResolver(cfg.ECS),
		condUpstream,
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

	cfg := s.cfg.Load()

	if cfg.Redis.IsEnabled() {
		logger().Info("Redis:")
		log.WithIndent(logger(), "  ", cfg.Redis.LogConfig)
	}

	resolver.ForEach(s.getQueryResolver(), func(res resolver.Resolver) {
		resolver.LogResolverConfig(res, logger())
	})

	logger().Info("listeners:")
	log.WithIndent(logger(), "  ", cfg.Ports.LogConfig)

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

// Start starts the server
func (s *Server) Start(ctx context.Context, errCh chan<- error) {
	logger().Info("Starting server")

	for _, srv := range s.dnsServers {
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				errCh <- fmt.Errorf("start %s listener failed: %w", srv.Net, err)
			}
		}()
	}

	for listener, srv := range s.servers {
		go func() {
			logger().Infof("%s server is up and running on addr/port %s", srv, listener.Addr())

			err := srv.Serve(ctx, listener)
			if err != nil {
				errCh <- fmt.Errorf("%s on %s: %w", srv, listener.Addr(), err)
			}
		}()
	}

	registerPrintConfigurationTrigger(ctx, s)
	registerReloadTrigger(ctx, s)
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
	timeoutDuration := time.Duration(contextUpstreamTimeoutMultiplier) * s.cfg.Load().Upstreams.Timeout.ToDuration()

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

		response, err = s.getQueryResolver().Resolve(ctx, request)
		if err != nil {
			var upstreamErr *resolver.UpstreamServerError

			if errors.As(err, &upstreamErr) {
				response = &model.Response{Res: upstreamErr.Msg, RType: model.ResponseTypeRESOLVED, Reason: upstreamErr.Error()}
			} else {
				return nil, fmt.Errorf("query resolution failed: %w", err)
			}
		}
	}

	response.Res.RecursionAvailable = request.Req.RecursionDesired

	// truncate if necessary
	response.Res.Truncate(getMaxResponseSize(request))

	// enable compression
	response.Res.Compress = true

	return response, nil
}

// For TCP returns 64k
// For UDP returns EDNS UDP size or if not present, 512
func getMaxResponseSize(req *model.Request) int {
	if req.Protocol == model.RequestProtocolTCP {
		return dns.MaxMsgSize
	}

	edns := req.Req.IsEdns0()
	if edns != nil && edns.UDPSize() > 0 {
		return int(edns.UDPSize())
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
