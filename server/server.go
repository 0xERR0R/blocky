// Modified by Chris Snell, 2026
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/auth"
	"github.com/0xERR0R/blocky/cache"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/configstore"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/logstream"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/pkg/advertise"
	"github.com/0xERR0R/blocky/pkg/statscollector"
	"github.com/0xERR0R/blocky/redis"
	"github.com/0xERR0R/blocky/resolver"
	"github.com/0xERR0R/blocky/server/freebind"

	"github.com/0xERR0R/blocky/util"
	goredis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"

	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"github.com/pires/go-proxyproto"
	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
)

const (
	maxUDPBufferSize = 65535
	caExpiryYears    = 10
	certExpiryYears  = 5

	networkUDP    = "udp"
	networkTCP    = "tcp"
	networkTCPTLS = "tcp-tls"
)

// chainSnapshot holds a resolver chain for atomic swap.
type chainSnapshot struct {
	chain  resolver.ChainedResolver
	cancel context.CancelFunc
}

// Server controls the endpoints for DNS and HTTP
type Server struct {
	dnsServers  []*dns.Server
	activeChain atomic.Pointer[chainSnapshot]
	cfg         *config.Config
	cfgMu       sync.RWMutex

	configStore *configstore.ConfigStore
	bootstrap   *resolver.Bootstrap
	// newCacheDecorator builds the caching resolver's write-through decorator
	// for a chain being constructed under a given context. It replaces the
	// *redis.Client the chain used to take: upstream moved redis from a
	// parameter of the blocking resolver to a decorator around the result
	// cache. Reconfigure must pass its own chain context, not the server's, or
	// the decorated cache outlives the chain that owns it.
	newCacheDecorator func(chainCtx context.Context) resolver.CacheDecorator
	broadcaster       *logstream.Broadcaster
	statsCollector    *statscollector.Collector
	wsRevoker         *auth.WSRevoker

	servers          map[net.Listener]*httpServer
	http3Server      *http3Server     // nil when disabled
	http3PacketConns []net.PacketConn // one per address in ports.https
	closers          []io.Closer
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

	return cert, nil
}

func newTLSConfig(cfg *config.Config) (*tls.Config, error) {
	var cert tls.Certificate

	cert, err := retrieveCertificate(cfg)
	if err != nil {
		return nil, fmt.Errorf("can't retrieve cert: %w", err)
	}

	// #nosec G402 // See TLSVersion.validate
	res := &tls.Config{
		MinVersion:   uint16(cfg.MinTLSServeVer), //nolint:gosec // TLS version constants fit safely in uint16
		CipherSuites: tlsCipherSuites(),
		Certificates: []tls.Certificate{cert},
	}

	return res, nil
}

// NewServer creates new server instance with passed config
//
//nolint:funlen
func NewServer(ctx context.Context, cfg *config.Config, store *configstore.ConfigStore) (server *Server, err error) {
	var tlsCfg *tls.Config

	if len(cfg.Ports.HTTPS) > 0 || len(cfg.Ports.TLS) > 0 || len(cfg.Ports.AdminPortTLS) > 0 {
		tlsCfg, err = newTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS configuration: %w", err)
		}
	}

	if cfg.Ports.FreeBind && !freebind.Supported {
		logger().Warn("ports.freeBind: true is only supported on Linux; " +
			"ignoring on this platform (binding normally)")
	}

	dnsServers, err := createServers(ctx, cfg, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("server creation failed: %w", err)
	}

	httpListeners, httpsListeners, http3PacketConns, err := createHTTPListeners(ctx, cfg, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP/HTTPS listeners: %w", err)
	}

	metrics.RegisterEventListeners()

	bootstrap, err := resolver.NewBootstrap(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create bootstrap resolver: %w", err)
	}

	var redisConn *goredis.Client
	if cfg.Redis.IsEnabled() {
		redisConn, err = redis.New(ctx, &cfg.Redis)
		if err != nil {
			if cfg.Redis.Required {
				return nil, fmt.Errorf("failed to create required Redis client: %w", err)
			}

			logger().WithError(err).Warn("Redis is enabled but optional and could not be initialized, continuing without Redis")
		}
	}

	redisResult, err := createRedisCacheDecorator(ctx, redisConn, cfg.Redis.Required)
	if err != nil {
		return nil, err
	}

	broadcaster := logstream.NewBroadcaster(ctx, 1000)
	log.Log().AddHook(logstream.NewHook(broadcaster))

	var scOpts []statscollector.Option
	if store != nil {
		scOpts = append(scOpts, statscollector.WithStore(store))
	}

	sc := statscollector.New(scOpts...)

	chainCtx, chainCancel := context.WithCancel(ctx)

	queryResolver, queryError := createQueryResolver(chainCtx, cfg, bootstrap,
		redisResult.decoratorFor(chainCtx), broadcaster, sc)
	if queryError != nil {
		chainCancel()

		return nil, queryError
	}

	// WSRevoker is created unconditionally so route registration can pass
	// it through; StartRevoker is only launched when a store is present
	// (the revocation channel originates in the store). When store is nil,
	// the revoker exists but no producer pushes to SessionRevoked, which is
	// a harmless idle state.
	wsRevoker := auth.NewWSRevoker()

	server = &Server{
		dnsServers:        dnsServers,
		cfg:               cfg,
		configStore:       store,
		bootstrap:         bootstrap,
		newCacheDecorator: redisResult.decoratorFor,
		broadcaster:       broadcaster,
		statsCollector:    sc,
		wsRevoker:         wsRevoker,

		servers:          make(map[net.Listener]*httpServer),
		http3PacketConns: http3PacketConns,
	}

	if redisResult.bridge != nil {
		server.closers = append(server.closers, redisResult.bridge)
	}

	if redisConn != nil {
		server.closers = append(server.closers, redisConn)
	}

	// Start the session-revocation consumer goroutine. It drains
	// store.SessionRevoked() for the lifetime of ctx and force-closes any
	// registered WebSocket when a user's sessions are revoked.
	if store != nil {
		auth.StartRevoker(ctx, store, wsRevoker)
	}

	server.activeChain.Store(&chainSnapshot{chain: queryResolver, cancel: chainCancel})

	server.printConfiguration()

	server.registerDNSHandlers(ctx)

	openAPIImpl, err := server.createOpenAPIInterfaceImpl()
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenAPI interface implementation: %w", err)
	}

	// mainRouter serves ports.http / ports.https — and, via HTTP/3, the UDP
	// mirrors of ports.https. With the admin UI on its own ports it carries
	// DoH only; otherwise it carries DoH plus the UI and the REST API.
	var (
		mainRouter *chi.Mux
		httpName   = "http"
		httpsName  = "https"
	)

	if cfg.Ports.AdminPortEnabled() {
		httpName, httpsName = "http-doh", "https-doh"

		// DoH-only router for main http/https ports
		dohRouter := chi.NewRouter()
		server.registerDoHEndpoints(dohRouter, cfg)
		mainRouter = dohRouter

		// UI-only router for admin ports
		uiRouter := chi.NewRouter()
		registerUIRoutes(uiRouter, cfg, openAPIImpl, server.configStore, server, server.broadcaster,
			server.statsCollector, server.wsRevoker)

		// Create admin listeners
		adminHTTP, adminHTTPS, err := createAdminListeners(ctx, cfg, tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create admin listeners: %w", err)
		}

		if len(cfg.Ports.AdminPort) != 0 {
			srv := newHTTPServer("http-admin", uiRouter)
			for _, l := range adminHTTP {
				server.servers[l] = srv
			}
		}

		if len(cfg.Ports.AdminPortTLS) != 0 {
			srv := newHTTPServer("https-admin", uiRouter)
			for _, l := range adminHTTPS {
				server.servers[l] = srv
			}
		}
	} else {
		httpRouter := createHTTPRouter(cfg, openAPIImpl, server.configStore, server, server.broadcaster,
			server.statsCollector, server.wsRevoker)
		server.registerDoHEndpoints(httpRouter, cfg)
		mainRouter = httpRouter
	}

	// HTTP/3 listens on the UDP counterparts of ports.https, so it serves
	// whatever that port serves — DoH only when the admin UI is split off.
	if len(http3PacketConns) > 0 {
		server.http3Server = newHTTP3Server(mainRouter, newH3TLSConfig(tlsCfg))
	}

	if len(cfg.Ports.HTTP) != 0 {
		srv := newHTTPServer(httpName, mainRouter)
		for _, l := range httpListeners {
			server.servers[l] = srv
		}
	}

	if len(cfg.Ports.HTTPS) != 0 {
		var httpsHandler http.Handler = mainRouter
		if server.http3Server != nil {
			httpsHandler = newAltSvcMiddleware(server.http3Server)(mainRouter)
		}

		srv := newHTTPServer(httpsName, httpsHandler)
		for _, l := range httpsListeners {
			server.servers[l] = srv
		}
	}

	// Start hourly session cleanup. Prune once at startup so a short-lived
	// process doesn't leave expired rows for an hour, then tick every hour
	// until the server context is cancelled. Per-tick errors are warn-logged
	// and do not exit the goroutine — the next tick will retry.
	if store != nil {
		go func() {
			if err := store.PruneExpiredSessions(); err != nil {
				logger().WithError(err).Warn("prune expired sessions at startup failed")
			}

			ticker := time.NewTicker(time.Hour)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := store.PruneExpiredSessions(); err != nil {
						logger().WithError(err).Warn("prune expired sessions failed")
					}
				}
			}
		}()
	}

	return server, err
}

func createServers(ctx context.Context, cfg *config.Config, tlsCfg *tls.Config) ([]*dns.Server, error) {
	var dnsServers []*dns.Server

	var err *multierror.Error

	freeBind := cfg.Ports.FreeBind

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
		addServers(func(address string) (*dns.Server, error) {
			return createUDPServer(ctx, address, listenerOptions{freeBind: freeBind})
		}, cfg.Ports.DNS),
		addServers(func(address string) (*dns.Server, error) {
			return createTCPServer(ctx, address, listenerOptions{
				freeBind:      freeBind,
				proxyProtocol: cfg.Ports.ProxyProtocol.Has(config.ProxyProtocolTypeDns),
			})
		}, cfg.Ports.DNS),
		addServers(func(address string) (*dns.Server, error) {
			return createTLSServer(ctx, address, tlsCfg, listenerOptions{
				freeBind:      freeBind,
				proxyProtocol: cfg.Ports.ProxyProtocol.Has(config.ProxyProtocolTypeTls),
			})
		}, cfg.Ports.TLS))

	if multiErr := err.ErrorOrNil(); multiErr != nil {
		return nil, fmt.Errorf("failed to create DNS servers: %w", multiErr)
	}

	return dnsServers, nil
}

func createHTTPListeners(
	ctx context.Context, cfg *config.Config, tlsCfg *tls.Config,
) (httpListeners, httpsListeners []net.Listener, http3PacketConns []net.PacketConn, err error) {
	httpListeners, err = newTCPListeners(ctx, "http", cfg.Ports.HTTP,
		cfg.Ports.ProxyProtocol.Has(config.ProxyProtocolTypeHttp))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create HTTP listeners: %w", err)
	}

	httpsListeners, err = newTLSListeners(ctx, "https", cfg.Ports.HTTPS, tlsCfg,
		cfg.Ports.ProxyProtocol.Has(config.ProxyProtocolTypeHttps))
	if err != nil {
		closeAll(httpListeners)

		return nil, nil, nil, fmt.Errorf("failed to create HTTPS listeners: %w", err)
	}

	if cfg.HTTP3.IsEnabled() {
		switch {
		case len(cfg.Ports.HTTPS) == 0:
			logger().Warn("http3.enable is true but ports.https is empty; HTTP/3 disabled")
		case cfg.Ports.ProxyProtocol.Has(config.ProxyProtocolTypeHttps):
			logger().Warn("http3.enable is true but ports.proxyProtocol includes 'https'; " +
				"HTTP/3 cannot carry PROXY protocol headers and is disabled to keep the client IP consistent")
		default:
			http3PacketConns, err = newUDPPacketConns(ctx, cfg.Ports.HTTPS)
			if err != nil {
				closeAll(httpListeners)
				closeAll(httpsListeners)

				return nil, nil, nil, fmt.Errorf("failed to create HTTP/3 UDP listeners: %w", err)
			}
		}
	}

	return httpListeners, httpsListeners, http3PacketConns, nil
}

func closeAll[T io.Closer](closers []T) {
	for _, c := range closers {
		_ = c.Close()
	}
}

// createAdminListeners opens the admin UI ports. PROXY protocol is never
// enabled on them: ports.proxyProtocol only names dns, tls, http and https,
// and the admin UI is not one of them, so there is no way to ask for it here.
func createAdminListeners(
	ctx context.Context, cfg *config.Config, tlsCfg *tls.Config,
) (httpListeners, httpsListeners []net.Listener, err error) {
	httpListeners, err = newTCPListeners(ctx, "http-admin", cfg.Ports.AdminPort, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create admin HTTP listeners: %w", err)
	}

	httpsListeners, err = newTLSListeners(ctx, "https-admin", cfg.Ports.AdminPortTLS, tlsCfg, false)
	if err != nil {
		closeAll(httpListeners)

		return nil, nil, fmt.Errorf("failed to create admin HTTPS listeners: %w", err)
	}

	return httpListeners, httpsListeners, nil
}

func newTCPListeners(
	ctx context.Context, proto string, addresses config.ListenConfig, proxyProtocol bool,
) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, len(addresses))
	lc := &net.ListenConfig{}

	for _, address := range addresses {
		listener, err := lc.Listen(ctx, networkTCP, address)
		if err != nil {
			return nil, fmt.Errorf("start %s listener on %s failed: %w", proto, address, err)
		}

		listener = newProxyProtocolListener(listener, proxyProtocol)

		listeners = append(listeners, listener)
	}

	return listeners, nil
}

func newTLSListeners(
	ctx context.Context, proto string, addresses config.ListenConfig, tlsCfg *tls.Config, proxyProtocol bool,
) ([]net.Listener, error) {
	listeners, err := newTCPListeners(ctx, proto, addresses, proxyProtocol)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP listeners for TLS: %w", err)
	}

	for i, inner := range listeners {
		listeners[i] = tls.NewListener(inner, tlsCfg)
	}

	return listeners, nil
}

func newProxyProtocolListener(listener net.Listener, enabled bool) net.Listener {
	if !enabled {
		return listener
	}

	return &proxyproto.Listener{
		Listener: listener,
		ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		},
	}
}

// listenerOptions bundles the socket-level options applied when a DNS listener is pre-created
// before miekg/dns starts serving (freebind socket option, PROXY protocol wrapping).
type listenerOptions struct {
	freeBind      bool
	proxyProtocol bool
}

func createDNSServer(ctx context.Context, network, address string, tlsCfg *tls.Config, opts listenerOptions,
) (*dns.Server, error) {
	srv := &dns.Server{
		Addr:    address,
		Net:     network,
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			logger().Infof("%s server is up and running on address %s", strings.ToUpper(network), address)
		},
	}

	if network == networkUDP {
		srv.UDPSize = maxUDPBufferSize
	}

	if tlsCfg != nil {
		srv.TLSConfig = tlsCfg
	}

	// When freeBind is enabled (and supported), pre-create the listener with the IP_FREEBIND socket
	// option and hand it to the server, which is then started via ActivateAndServe (see Server.Start).
	if (opts.freeBind && freebind.Supported) || (opts.proxyProtocol && network != networkUDP) {
		if err := attachListener(ctx, srv, network, address, tlsCfg, listenerOptions{
			freeBind:      opts.freeBind && freebind.Supported,
			proxyProtocol: opts.proxyProtocol,
		}); err != nil {
			return nil, err
		}
	}

	return srv, nil
}

// attachListener creates a listener/packet connection for DNS servers that need custom socket handling
// before miekg/dns starts serving, such as freebind or PROXY protocol wrapping.
func attachListener(ctx context.Context, srv *dns.Server, network, address string,
	tlsCfg *tls.Config, opts listenerOptions,
) error {
	lc := net.ListenConfig{}
	if opts.freeBind {
		lc.Control = freebind.Control
	}

	switch network {
	case networkUDP:
		pc, err := lc.ListenPacket(ctx, networkUDP, address)
		if err != nil {
			return fmt.Errorf("freebind udp listener on %s failed: %w", address, err)
		}

		srv.PacketConn = pc
	case networkTCP:
		l, err := lc.Listen(ctx, networkTCP, address)
		if err != nil {
			return fmt.Errorf("tcp listener on %s failed: %w", address, err)
		}

		l = newProxyProtocolListener(l, opts.proxyProtocol)
		srv.Listener = l
	case networkTCPTLS:
		l, err := lc.Listen(ctx, networkTCP, address)
		if err != nil {
			return fmt.Errorf("tcp-tls listener on %s failed: %w", address, err)
		}

		l = newProxyProtocolListener(l, opts.proxyProtocol)
		srv.Listener = tls.NewListener(l, tlsCfg)
	default:
		return fmt.Errorf("unsupported DNS listener network %q", network)
	}

	return nil
}

func createTLSServer(ctx context.Context, address string, tlsCfg *tls.Config, opts listenerOptions,
) (*dns.Server, error) {
	return createDNSServer(ctx, networkTCPTLS, address, tlsCfg, opts)
}

func createTCPServer(ctx context.Context, address string, opts listenerOptions) (*dns.Server, error) {
	return createDNSServer(ctx, networkTCP, address, nil, opts)
}

func createUDPServer(ctx context.Context, address string, opts listenerOptions) (*dns.Server, error) {
	return createDNSServer(ctx, networkUDP, address, nil, opts)
}

type redisBridgeResult struct {
	// decoratorFor builds the decorator for a chain being constructed under
	// chainCtx, rather than a single decorator captured at startup. The
	// Redis-backed cache launches a subscriber and a batching writer that run
	// until their context is cancelled (see cache.NewRedisExpiringCache), so a
	// decorator bound to the server context would leak one set of goroutines —
	// plus the cache they feed — on every Reconfigure. It returns nil when
	// Redis is not configured, which is what disables the decoration.
	decoratorFor func(chainCtx context.Context) resolver.CacheDecorator
	bridge       *redis.EventBusBridge
}

func createRedisCacheDecorator(
	ctx context.Context, redisConn *goredis.Client, required bool,
) (*redisBridgeResult, error) {
	if redisConn == nil {
		return &redisBridgeResult{
			decoratorFor: func(context.Context) resolver.CacheDecorator { return nil },
		}, nil
	}

	bridge, err := redis.NewEventBusBridge(ctx, redisConn)
	if err != nil {
		if required {
			return nil, fmt.Errorf("failed to create required Redis event bridge: %w", err)
		}

		logger().Warn("failed to create Redis event bridge: ", err)
	}

	decoratorFor := func(chainCtx context.Context) resolver.CacheDecorator {
		return func(inner cache.ExpiringCache[[]byte]) (cache.ExpiringCache[[]byte], error) {
			return cache.NewRedisExpiringByteCache(chainCtx, inner, redisConn, cache.RedisOptions[[]byte]{
				Prefix:  "blocky:cache:",
				Channel: "blocky_cache_sync",
			})
		}
	}

	return &redisBridgeResult{decoratorFor: decoratorFor, bridge: bridge}, nil
}

func createQueryResolver(
	ctx context.Context,
	cfg *config.Config,
	bootstrap *resolver.Bootstrap,
	cacheDecorator resolver.CacheDecorator,
	broadcaster *logstream.Broadcaster,
	statsCollector *statscollector.Collector,
) (resolver.ChainedResolver, error) {
	upstreamTree, utErr := resolver.NewUpstreamTreeResolver(ctx, cfg.Upstreams, bootstrap)
	blocking, blErr := resolver.NewBlockingResolver(ctx, cfg.Blocking, bootstrap)
	queryLogging, qlErr := resolver.NewQueryLoggingResolver(ctx, cfg.QueryLog, broadcaster)
	condUpstream, cuErr := resolver.NewConditionalUpstreamResolver(ctx, cfg.Conditional, cfg.Upstreams, bootstrap)
	customDNS := resolver.NewCustomDNSResolver(cfg.CustomDNS)
	hostsFile, hfErr := resolver.NewHostsFileResolver(ctx, cfg.HostsFile, bootstrap)
	// client name resolution consults local reverse sources (custom DNS, hosts file) before the rDNS upstream
	clientNames, cnErr := resolver.NewClientNamesResolver(
		ctx, cfg.ClientLookup, cfg.Upstreams, bootstrap, customDNS, hostsFile)
	decorator := cacheDecorator
	if !cfg.Caching.IsEnabled() {
		decorator = nil
	}

	// cfg.DNSSEC gates the DO bit on prefetch reloads (they bypass the DNSSEC
	// resolver above the cache).
	cachingResolver, crErr := resolver.NewCachingResolver(ctx, cfg.Caching, cfg.DNSSEC, decorator)
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

	metricsResolver := resolver.NewMetricsResolver(cfg.Prometheus)
	metricsResolver.StatsCollector = statsCollector

	r := resolver.Chain(
		// stays above the ECS and client-name lookups: its bucket key must remain the
		// connection's source IP. Keyed on the ECS address instead (ecs.useAsClient), the
		// key would be attacker-controlled, letting a client both evade its own bucket and
		// fill the bounded bucket store, which drops queries of every new client once full.
		// Dropped queries therefore carry no client name and are attributed to the client
		// IP in the statistics.
		resolver.NewRateLimitingResolver(ctx, cfg.RateLimit),
		// adopts the ECS subnet as the internal client IP (ecs.useAsClient) before the
		// client-name lookup, blocking and the cache consume the client identity, so the
		// ECS client is used for those features and is preserved across cache hits
		resolver.NewECSClientResolver(cfg.ECS),
		// above filtering and fqdnOnly, which answer a query on their own: a lookup below
		// them would leave request.ClientNames empty for every query they short-circuit,
		// and the statistics would attribute those to the raw client IP while the same
		// client's other queries are attributed to its name
		clientNames,
		resolver.NewFilteringResolver(cfg.Filtering),
		resolver.NewFQDNOnlyResolver(cfg.FQDNOnly),
		resolver.NewEDEResolver(cfg.EDE),
		queryLogging,
		metricsResolver,
		customDNS,
		hostsFile,
		// above blocking and the cache: it inspects only RESOLVED/CACHED answers
		// (conditional/custom DNS/hosts file/SUDN/blocked answers are recognized
		// by response type and pass through; the cache stores only
		// upstream-derived answers, so CACHED implies upstream origin), cached
		// answers — incl. entries synced via redis — are re-inspected on every
		// hit, and blocking's internal FQDN client-identifier lookups enter the
		// chain below it
		resolver.NewRebindingProtectionResolver(cfg.RebindingProtection),
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
		//nolint:forcetypeassert // handler is always *dns.ServeMux; set during server construction
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

	resolver.ForEach(s.activeChain.Load().chain, func(res resolver.Resolver) {
		resolver.LogResolverConfig(res, logger())
	})

	logger().Info("listeners:")
	log.WithIndent(logger(), "  ", s.cfg.Ports.LogConfig)

	if len(s.http3PacketConns) > 0 {
		logger().Info("HTTP/3:")
		log.WithIndent(logger(), "  ", s.cfg.HTTP3.LogConfig)
	}

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
			// When a listener/packet connection was pre-created (freeBind), serve it via
			// ActivateAndServe; otherwise let miekg/dns create the socket via ListenAndServe.
			serve := srv.ListenAndServe
			if srv.Listener != nil || srv.PacketConn != nil {
				serve = srv.ActivateAndServe
			}

			if err := serve(); err != nil {
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

	if s.http3Server != nil {
		for _, pc := range s.http3PacketConns {
			go func() {
				logger().Infof("%s server is up and running on addr/port %s",
					s.http3Server, pc.LocalAddr())

				err := s.http3Server.inner.Serve(pc)
				if err != nil &&
					!errors.Is(err, quic.ErrServerClosed) &&
					!errors.Is(err, http.ErrServerClosed) &&
					!errors.Is(err, net.ErrClosed) {
					errCh <- fmt.Errorf("%s on %s: %w", s.http3Server, pc.LocalAddr(), err)
				}
			}()
		}
	}

	registerPrintConfigurationTrigger(ctx, s)
}

// Stop stops the server
func (s *Server) Stop(ctx context.Context) error {
	logger().Info("Stopping server")

	if s.statsCollector != nil {
		s.statsCollector.Close()
	}

	if s.broadcaster != nil {
		s.broadcaster.Shutdown()
	}

	// Shut down HTTP/3 in order: server first (drains in-flight
	// requests and unblocks the Serve goroutines), then UDP packet
	// conns. Closing the packet conns first would cause Serve to
	// return a non-sentinel error that would land in errCh as a
	// spurious "server start failed".
	if s.http3Server != nil {
		if err := s.http3Server.Close(); err != nil {
			logger().Warn("failed to close http3 server: ", err)
		}
	}

	for _, pc := range s.http3PacketConns {
		if err := pc.Close(); err != nil {
			logger().Warn("failed to close http3 packet conn: ", err)
		}
	}

	for _, c := range s.closers {
		if err := c.Close(); err != nil {
			logger().Warn("failed to close resource: ", err)
		}
	}

	// Every listener gets a shutdown attempt even if an earlier one fails:
	// returning on the first error used to leave the remaining DNS servers
	// running and the HTTP ports bound.
	var errs []error

	for _, server := range s.dnsServers {
		if err := server.ShutdownContext(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stop %s listener failed: %w", server.Net, err))
		}
	}

	// The HTTP and HTTPS listeners were previously released only by the
	// context-cancellation goroutine in httpServer.Serve. That made Stop a
	// promise it did not keep: the ports could still be bound when it
	// returned, so anything rebinding them straight afterwards — a restart, or
	// the next test in a suite — hit "address already in use" depending on
	// goroutine scheduling.
	for listener, srv := range s.servers {
		if err := srv.Close(ctx, listener); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// Reconfigure rebuilds the resolver chain from current DB state.
// On error, the old chain stays active.
func (s *Server) Reconfigure(ctx context.Context) error {
	if s.configStore == nil {
		return errors.New("no config store configured")
	}

	// Snapshot config under read lock
	s.cfgMu.RLock()
	newCfg := *s.cfg
	s.cfgMu.RUnlock()

	// Build new config from DB
	blocking, err := s.configStore.BuildBlockingConfig(newCfg.Blocking)
	if err != nil {
		return fmt.Errorf("building blocking config: %w", err)
	}

	customDNS, err := s.configStore.BuildCustomDNSConfig(newCfg.CustomDNS)
	if err != nil {
		return fmt.Errorf("building custom DNS config: %w", err)
	}

	upstreams, err := s.configStore.BuildUpstreamsConfig(newCfg.Upstreams)
	if err != nil {
		return fmt.Errorf("building upstreams config: %w", err)
	}

	newCfg.Blocking = blocking
	newCfg.CustomDNS = customDNS
	newCfg.Upstreams = upstreams

	// Re-inject auto-advertise DNS records for client group endpoint domains
	cge := newCfg.ClientGroupEndpoints
	if cge.AdvertiseAddress != "" && len(cge.Domains) > 0 {
		ip, advErr := advertise.ResolveAddress(cge.AdvertiseAddress)
		if advErr != nil {
			logger().Warnf("advertise address resolution failed during reconfigure: %v", advErr)
		} else if ip != nil {
			if newCfg.CustomDNS.Mapping == nil {
				newCfg.CustomDNS.Mapping = make(config.CustomDNSMapping)
			}

			const advertiseTTL = 3600
			advertise.InjectRecords(newCfg.CustomDNS.Mapping, cge.Domains, ip, advertiseTTL)
		}
	}

	// Build new resolver chain (slow — list loading, network I/O)
	// Use Background context, not the caller's ctx (which may be an HTTP request
	// context that gets cancelled when the response is sent, killing goroutines
	// like writeLog that need to run for the lifetime of the chain).
	chainCtx, chainCancel := context.WithCancel(context.Background())

	newChain, err := createQueryResolver(chainCtx, &newCfg, s.bootstrap,
		s.newCacheDecorator(chainCtx), s.broadcaster, s.statsCollector)
	if err != nil {
		chainCancel()

		return fmt.Errorf("creating resolver chain: %w", err)
	}

	// Atomic swap — only on success
	snap := &chainSnapshot{chain: newChain, cancel: chainCancel}
	old := s.activeChain.Swap(snap)

	// Update stored config
	s.cfgMu.Lock()
	s.cfg.Blocking = blocking
	s.cfg.CustomDNS = customDNS
	s.cfg.Upstreams = upstreams
	s.cfgMu.Unlock()

	// Cancel old chain context (in-flight queries drain naturally)
	if old != nil && old.cancel != nil {
		old.cancel()
	}

	logger().Info("Configuration reloaded successfully")

	return nil
}

// extractClientIDFromHost extracts a client group slug from a hostname
// by matching against configured base domains.
// e.g., "kids-devices.dns.example.com" with base "dns.example.com" → "kids-devices"
func extractClientIDFromHost(hostName string, baseDomains []string) string {
	host := strings.ToLower(strings.TrimSuffix(hostName, "."))

	for _, base := range baseDomains {
		suffix := "." + strings.ToLower(base)
		if before, ok := strings.CutSuffix(host, suffix); ok {
			label := before
			if !strings.Contains(label, ".") && label != "" {
				return label
			}
		}
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

func (s *Server) newRequestFromDNS(ctx context.Context, rw dns.ResponseWriter, msg *dns.Msg) (context.Context, *model.Request) {
	var (
		clientIP net.IP
		protocol model.RequestProtocol
	)

	if rw != nil {
		clientIP, protocol = resolveClientIPAndProtocol(rw.RemoteAddr())
	}

	domains := s.cfg.ClientGroupEndpoints.Domains

	var clientID string
	if con, ok := rw.(dns.ConnectionStater); ok && con.ConnectionState() != nil {
		clientID = extractClientIDFromHost(con.ConnectionState().ServerName, domains)
	}

	// Fall back to EDNS CPE-ID for plain DNS
	if clientID == "" && s.cfg.ClientGroupEndpoints.CpeID {
		clientID = util.ExtractCpeID(msg)
	}

	return newRequest(ctx, clientIP, clientID, protocol, msg)
}

func (s *Server) newRequestFromHTTP(ctx context.Context, req *http.Request, msg *dns.Msg) (context.Context, *model.Request) {
	protocol := model.RequestProtocolTCP
	clientIP := util.HTTPClientIP(req)

	clientID := chi.URLParam(req, "clientID")
	if clientID == "" {
		clientID = extractClientIDFromHost(req.Host, s.cfg.ClientGroupEndpoints.Domains)
	}

	return newRequest(ctx, clientIP, clientID, protocol, msg)
}

// OnRequest will be executed if a new DNS request is received
func (s *Server) OnRequest(ctx context.Context, w dns.ResponseWriter, msg *dns.Msg) {
	ctx, request := s.newRequestFromDNS(ctx, w, msg)

	s.handleReq(ctx, request, w)
}

type msgWriter interface {
	WriteMsg(msg *dns.Msg) error
}

func (s *Server) handleReq(ctx context.Context, request *model.Request, w msgWriter) {
	response, err := s.resolve(ctx, request)
	switch {
	case errors.Is(err, resolver.ErrRateLimited):
		return
	case err != nil:
		log.FromCtx(ctx).Error("error on processing request:", err)
		m := new(dns.Msg)
		m.SetRcode(request.Req, dns.RcodeServerFailure)
		err := w.WriteMsg(m)
		util.LogOnError(ctx, "can't write message: ", err)
	default:
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

	// The resolver chain mutates request.Req in place, so capture what the client itself asked for
	// up front: the response is normalized against that, not the mutated request.
	query := newClientQuery(request)

	// Blocky doesn't implement DNS Cookies (RFC 7873), so a Server Cookie a client returns is one
	// an upstream issued and blocky can neither validate nor reissue it. Forwarding it is worse
	// than dropping it: it is likely to reach a different upstream than the one that issued it
	// (`parallel_best` picks at random), which can't validate it either and may answer BADCOOKIE.
	// The OPT record itself is kept, since it still carries the DO bit and the buffer size the
	// client advertised.
	util.RemoveEdns0OptionKeepRecord[*dns.EDNS0_COOKIE](request.Req)

	switch {
	case len(request.Req.Question) == 0:
		m := new(dns.Msg)
		m.SetRcode(request.Req, dns.RcodeFormatError)

		log.FromCtx(ctx).Error("query has no questions")

		response = &model.Response{Res: m, RType: model.ResponseTypeCUSTOMDNS, Reason: "CUSTOM DNS"}
	default:
		var err error

		response, err = s.activeChain.Load().chain.Resolve(ctx, request)
		if err != nil {
			var upstreamErr *resolver.UpstreamServerError

			if errors.As(err, &upstreamErr) {
				response = &model.Response{Res: upstreamErr.Msg, RType: model.ResponseTypeRESOLVED, Reason: upstreamErr.Error()}
			} else {
				return nil, fmt.Errorf("query resolution failed: %w", err)
			}
		}
	}

	query.normalizeResponse(response.Res)

	return response, nil
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
