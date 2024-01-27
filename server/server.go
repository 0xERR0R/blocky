package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
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

// Server controls the endpoints for DNS and HTTP
type Server struct {
	dnsServers     []*dns.Server
	httpListeners  []net.Listener
	httpsListeners []net.Listener
	queryResolver  resolver.ChainedResolver
	cfg            *config.Config
	httpMux        *chi.Mux
	httpsMux       *chi.Mux
	cert           tls.Certificate
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

func getServerAddress(addr string) string {
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf(":%s", addr)
	}

	return addr
}

type NewServerFunc func(address string) (*dns.Server, error)

func retrieveCertificate(cfg *config.Config) (cert tls.Certificate, err error) {
	if cfg.CertFile == "" && cfg.KeyFile == "" {
		cert, err = createSelfSignedCert()
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

// NewServer creates new server instance with passed config
//
//nolint:funlen
func NewServer(ctx context.Context, cfg *config.Config) (server *Server, err error) {
	var cert tls.Certificate

	if len(cfg.Ports.HTTPS) > 0 || len(cfg.Ports.TLS) > 0 {
		cert, err = retrieveCertificate(cfg)
		if err != nil {
			return nil, fmt.Errorf("can't retrieve cert: %w", err)
		}
	}

	dnsServers, err := createServers(cfg, cert)
	if err != nil {
		return nil, fmt.Errorf("server creation failed: %w", err)
	}

	httpRouter := createHTTPRouter(cfg)
	httpsRouter := createHTTPSRouter(cfg)

	httpListeners, httpsListeners, err := createHTTPListeners(cfg)
	if err != nil {
		return nil, err
	}

	if len(httpListeners) != 0 || len(httpsListeners) != 0 {
		metrics.Start(httpRouter, cfg.Prometheus)
		metrics.Start(httpsRouter, cfg.Prometheus)
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
		dnsServers:     dnsServers,
		queryResolver:  queryResolver,
		cfg:            cfg,
		httpListeners:  httpListeners,
		httpsListeners: httpsListeners,
		httpMux:        httpRouter,
		httpsMux:       httpsRouter,
		cert:           cert,
	}

	server.printConfiguration()

	server.registerDNSHandlers(ctx)
	err = server.registerAPIEndpoints(httpRouter)

	if err != nil {
		return nil, err
	}

	err = server.registerAPIEndpoints(httpsRouter)

	if err != nil {
		return nil, err
	}

	return server, err
}

func createServers(cfg *config.Config, cert tls.Certificate) ([]*dns.Server, error) {
	var dnsServers []*dns.Server

	var err *multierror.Error

	addServers := func(newServer NewServerFunc, addresses config.ListenConfig) error {
		for _, address := range addresses {
			server, err := newServer(getServerAddress(address))
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
			return createTLSServer(cfg, address, cert)
		}, cfg.Ports.TLS))

	return dnsServers, err.ErrorOrNil()
}

func createHTTPListeners(cfg *config.Config) (httpListeners, httpsListeners []net.Listener, err error) {
	httpListeners, err = newListeners("http", cfg.Ports.HTTP)
	if err != nil {
		return nil, nil, err
	}

	httpsListeners, err = newListeners("https", cfg.Ports.HTTPS)
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

func createTLSServer(cfg *config.Config, address string, cert tls.Certificate) (*dns.Server, error) {
	return &dns.Server{
		Addr: address,
		Net:  "tcp-tls",
		//nolint:gosec
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   uint16(cfg.MinTLSServeVer),
			CipherSuites: tlsCipherSuites(),
		},
		Handler: dns.NewServeMux(),
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

//nolint:funlen
func createSelfSignedCert() (tls.Certificate, error) {
	// Create CA
	ca := &x509.Certificate{
		//nolint:gosec
		SerialNumber:          big.NewInt(int64(mrand.Intn(math.MaxInt))),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(caExpiryYears, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	caPEM := new(bytes.Buffer)
	if err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		return tls.Certificate{}, err
	}

	caPrivKeyPEM := new(bytes.Buffer)

	b, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	if err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	}); err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate
	cert := &x509.Certificate{
		//nolint:gosec
		SerialNumber: big.NewInt(int64(mrand.Intn(math.MaxInt))),
		DNSNames:     []string{"*"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(certExpiryYears, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := new(bytes.Buffer)
	if err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return tls.Certificate{}, err
	}

	certPrivKeyPEM := new(bytes.Buffer)

	b, err = x509.MarshalECPrivateKey(certPrivKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	if err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	}); err != nil {
		return tls.Certificate{}, err
	}

	keyPair, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return tls.Certificate{}, err
	}

	return keyPair, nil
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
	condUpstream, cuErr := resolver.NewConditionalUpstreamResolver(ctx, cfg.Conditional, cfg.Upstreams, bootstrap)
	hostsFile, hfErr := resolver.NewHostsFileResolver(ctx, cfg.HostsFile, bootstrap)

	err := multierror.Append(
		multierror.Prefix(utErr, "upstream tree resolver: "),
		multierror.Prefix(blErr, "blocking resolver: "),
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
		resolver.NewQueryLoggingResolver(ctx, cfg.QueryLog),
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

const (
	readHeaderTimeout = 20 * time.Second
	readTimeout       = 20 * time.Second
	writeTimeout      = 20 * time.Second
)

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

	for i, listener := range s.httpListeners {
		listener := listener
		address := s.cfg.Ports.HTTP[i]

		go func() {
			logger().Infof("http server is up and running on addr/port %s", address)

			srv := &http.Server{
				ReadTimeout:       readTimeout,
				ReadHeaderTimeout: readHeaderTimeout,
				WriteTimeout:      writeTimeout,
				Handler:           s.httpsMux,
			}

			if err := srv.Serve(listener); err != nil {
				errCh <- fmt.Errorf("start http listener failed: %w", err)
			}
		}()
	}

	for i, listener := range s.httpsListeners {
		listener := listener
		address := s.cfg.Ports.HTTPS[i]

		go func() {
			logger().Infof("https server is up and running on addr/port %s", address)

			server := http.Server{
				Handler:           s.httpsMux,
				ReadTimeout:       readTimeout,
				ReadHeaderTimeout: readHeaderTimeout,
				WriteTimeout:      writeTimeout,
				//nolint:gosec
				TLSConfig: &tls.Config{
					MinVersion:   uint16(s.cfg.MinTLSServeVer),
					CipherSuites: tlsCipherSuites(),
					Certificates: []tls.Certificate{s.cert},
				},
			}

			if err := server.ServeTLS(listener, "", ""); err != nil {
				errCh <- fmt.Errorf("start https listener failed: %w", err)
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
