package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/redis"
	"github.com/0xERR0R/blocky/resolver"
	"github.com/0xERR0R/blocky/util"
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
	queryResolver  resolver.Resolver
	cfg            *config.Config
	httpMux        *chi.Mux
	httpsMux       *chi.Mux
	cert           tls.Certificate
}

func logger() *logrus.Entry {
	return log.PrefixedLog("server")
}

func minTLSVersion() uint16 {
	minTLSVer := config.GetConfig().MinTLSServeVer
	switch minTLSVer {
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		logger().Warn("Not allowed or supported mininum TLS version ", minTLSVer, ", fallback to TLS 1.3")

		return tls.VersionTLS13
	}
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
// nolint:funlen
func NewServer(cfg *config.Config) (server *Server, err error) {
	log.ConfigureLogger(cfg.LogLevel, cfg.LogFormat, cfg.LogTimestamp)

	var cert tls.Certificate

	if len(cfg.HTTPSPorts) > 0 || len(cfg.TLSPorts) > 0 {
		cert, err = retrieveCertificate(cfg)
		if err != nil {
			return nil, fmt.Errorf("can't retrieve cert: %w", err)
		}
	}

	dnsServers, err := createServers(cfg, cert)
	if err != nil {
		return nil, fmt.Errorf("server creation failed: %w", err)
	}

	httpRouter := createRouter(cfg)
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

	bootstrap, err := resolver.NewBootstrap(cfg)
	if err != nil {
		return nil, err
	}

	redisClient, redisErr := redis.New(&cfg.Redis)
	if redisErr != nil && cfg.Redis.Required {
		return nil, redisErr
	}

	queryResolver, queryError := createQueryResolver(cfg, bootstrap, redisClient)
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

	server.registerDNSHandlers()
	server.registerAPIEndpoints(httpRouter)
	server.registerAPIEndpoints(httpsRouter)

	registerResolverAPIEndpoints(httpRouter, queryResolver)
	registerResolverAPIEndpoints(httpsRouter, queryResolver)

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
		addServers(createUDPServer, cfg.DNSPorts),
		addServers(createTCPServer, cfg.DNSPorts),
		addServers(func(address string) (*dns.Server, error) {
			return createTLSServer(address, cert)
		}, cfg.TLSPorts))

	return dnsServers, err.ErrorOrNil()
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

func createTLSServer(address string, cert tls.Certificate) (*dns.Server, error) {
	return &dns.Server{
		Addr: address,
		Net:  "tcp-tls",
		//nolint:gosec
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   minTLSVersion(),
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

// nolint:funlen
func createSelfSignedCert() (tls.Certificate, error) {
	// Create CA
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(mrand.Intn(math.MaxInt))), //nolint:gosec
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
		SerialNumber: big.NewInt(int64(mrand.Intn(math.MaxInt))), //nolint:gosec
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
	cfg *config.Config,
	bootstrap *resolver.Bootstrap,
	redisClient *redis.Client,
) (r resolver.Resolver, err error) {
	blockingResolver, blErr := resolver.NewBlockingResolver(cfg.Blocking, redisClient, bootstrap)
	parallelResolver, pErr := resolver.NewParallelBestResolver(cfg.Upstream.ExternalResolvers, bootstrap)
	clientNamesResolver, cnErr := resolver.NewClientNamesResolver(cfg.ClientLookup, bootstrap)
	conditionalUpstreamResolver, cuErr := resolver.NewConditionalUpstreamResolver(cfg.Conditional, bootstrap)

	mErr := multierror.Append(
		multierror.Prefix(blErr, "blocking resolver: "),
		multierror.Prefix(pErr, "parallel resolver: "),
		multierror.Prefix(cnErr, "client names resolver: "),
		multierror.Prefix(cuErr, "conditional upstream resolver: "),
	)
	if mErr.ErrorOrNil() != nil {
		return nil, mErr
	}

	r = resolver.Chain(
		resolver.NewFilteringResolver(cfg.Filtering),
		resolver.NewFqdnOnlyResolver(*cfg),
		clientNamesResolver,
		resolver.NewEdeResolver(cfg.Ede),
		resolver.NewQueryLoggingResolver(cfg.QueryLog),
		resolver.NewMetricsResolver(cfg.Prometheus),
		resolver.NewRewriterResolver(cfg.CustomDNS.RewriteConfig, resolver.NewCustomDNSResolver(cfg.CustomDNS)),
		resolver.NewHostsFileResolver(cfg.HostsFile),
		blockingResolver,
		resolver.NewCachingResolver(cfg.Caching, redisClient),
		resolver.NewRewriterResolver(cfg.Conditional.RewriteConfig, conditionalUpstreamResolver),
		resolver.NewSpecialUseDomainNamesResolver(),
		parallelResolver,
	)

	return r, nil
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
	const bytesInKB = 1024

	return b / bytesInKB / bytesInKB
}

const (
	readHeaderTimeout = 20 * time.Second
	readTimeout       = 20 * time.Second
	writeTimeout      = 20 * time.Second
)

// Start starts the server
func (s *Server) Start(errCh chan<- error) {
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
		address := s.cfg.HTTPPorts[i]

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
		address := s.cfg.HTTPSPorts[i]

		go func() {
			logger().Infof("https server is up and running on addr/port %s", address)

			server := http.Server{
				Handler:           s.httpsMux,
				ReadTimeout:       readTimeout,
				ReadHeaderTimeout: readHeaderTimeout,
				WriteTimeout:      writeTimeout,
				//nolint:gosec
				TLSConfig: &tls.Config{
					MinVersion:   minTLSVersion(),
					CipherSuites: tlsCipherSuites(),
					Certificates: []tls.Certificate{s.cert},
				},
			}

			if err := server.ServeTLS(listener, "", ""); err != nil {
				errCh <- fmt.Errorf("start https listener failed: %w", err)
			}
		}()
	}

	registerPrintConfigurationTrigger(s)
}

// Stop stops the server
func (s *Server) Stop() error {
	logger().Info("Stopping server")

	for _, server := range s.dnsServers {
		if err := server.Shutdown(); err != nil {
			return fmt.Errorf("stop %s listener failed: %w", server.Net, err)
		}
	}

	return nil
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
		logger().Error("error on processing request:", err)

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

// returns EDNS UDP size or if not present, 512 for UDP and 64K for TCP
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
