// Modified by Chris Snell, 2026
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/0xERR0R/blocky/auth"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/pkg/arp"
	"github.com/0xERR0R/blocky/pkg/statscollector"
	"github.com/0xERR0R/blocky/resolver"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/api/configapi"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/configstore"
	"github.com/0xERR0R/blocky/docs"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/logstream"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/0xERR0R/blocky/web"

	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"nhooyr.io/websocket"
)

const (
	dohMessageLimit    = 512
	contentTypeHeader  = "Content-Type"
	cacheControlHeader = "Cache-Control"
	dnsContentType     = "application/dns-message"
	htmlContentType    = "text/html; charset=UTF-8"
	yamlContentType    = "text/yaml"
	jsonContentType    = "application/json"
)

// ResolverAccessor implementation — resolves from the current (possibly hot-swapped) chain.

func (s *Server) BlockingControl() (api.BlockingControl, error) {
	return resolver.GetFromChainWithType[api.BlockingControl](s.activeChain.Load().chain)
}

func (s *Server) ListRefresher() (api.ListRefresher, error) {
	return resolver.GetFromChainWithType[api.ListRefresher](s.activeChain.Load().chain)
}

func (s *Server) CacheControl() (api.CacheControl, error) {
	return resolver.GetFromChainWithType[api.CacheControl](s.activeChain.Load().chain)
}

func (s *Server) createOpenAPIInterfaceImpl() (impl api.StrictServerInterface, err error) {
	// Validate that the initial chain has the required resolver types
	if _, err := s.BlockingControl(); err != nil {
		return nil, fmt.Errorf("no blocking API implementation found %w", err)
	}

	if _, err := s.ListRefresher(); err != nil {
		return nil, fmt.Errorf("no refresh API implementation found %w", err)
	}

	if _, err := s.CacheControl(); err != nil {
		return nil, fmt.Errorf("no cache API implementation found %w", err)
	}

	return api.NewOpenAPIInterfaceImpl(s, s), nil
}

func (s *Server) registerDoHEndpoints(router *chi.Mux, cfg *config.Config) {
	pathDohQuery := cfg.Ports.DOHPath

	router.Get(pathDohQuery, s.dohGetRequestHandler)
	router.Get(pathDohQuery+"/", s.dohGetRequestHandler)
	router.Get(pathDohQuery+"/{clientID}", s.dohGetRequestHandler)
	router.Post(pathDohQuery, s.dohPostRequestHandler)
	router.Post(pathDohQuery+"/", s.dohPostRequestHandler)
	router.Post(pathDohQuery+"/{clientID}", s.dohPostRequestHandler)
}

func (s *Server) dohGetRequestHandler(rw http.ResponseWriter, req *http.Request) {
	dnsParam, ok := req.URL.Query()["dns"]
	if !ok || len(dnsParam[0]) < 1 {
		http.Error(rw, "dns param is missing", http.StatusBadRequest)

		return
	}

	if len(dnsParam[0]) > base64.RawURLEncoding.EncodedLen(dohMessageLimit) {
		http.Error(rw, "URI Too Long", http.StatusRequestURITooLong)

		return
	}

	rawMsg, err := base64.RawURLEncoding.DecodeString(dnsParam[0])
	if err != nil {
		http.Error(rw, "wrong message format", http.StatusBadRequest)

		return
	}

	if len(rawMsg) > dohMessageLimit {
		http.Error(rw, "URI Too Long", http.StatusRequestURITooLong)

		return
	}

	s.processDohMessage(rawMsg, rw, req)
}

func (s *Server) dohPostRequestHandler(rw http.ResponseWriter, req *http.Request) {
	contentType := req.Header.Get(contentTypeHeader)
	if contentType != dnsContentType {
		http.Error(rw, "unsupported content type", http.StatusUnsupportedMediaType)

		return
	}

	rawMsg, err := io.ReadAll(io.LimitReader(req.Body, int64(dohMessageLimit)+1))
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	if len(rawMsg) > dohMessageLimit {
		http.Error(rw, "Payload Too Large", http.StatusRequestEntityTooLarge)

		return
	}

	s.processDohMessage(rawMsg, rw, req)
}

func (s *Server) processDohMessage(rawMsg []byte, rw http.ResponseWriter, httpReq *http.Request) {
	msg := new(dns.Msg)
	if err := msg.Unpack(rawMsg); err != nil {
		logger().Error("can't deserialize message: ", err)
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	ctx, dnsReq := s.newRequestFromHTTP(httpReq.Context(), httpReq, msg)

	s.handleReq(ctx, dnsReq, httpMsgWriter{rw})
}

type httpMsgWriter struct {
	rw http.ResponseWriter
}

func (r httpMsgWriter) WriteMsg(msg *dns.Msg) error {
	b, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack DNS message for DoH response: %w", err)
	}

	r.rw.Header().Set(contentTypeHeader, dnsContentType)

	// https://www.rfc-editor.org/rfc/rfc8484#section-5.1
	// get the smallest TTL from answer
	r.rw.Header().Set(cacheControlHeader, fmt.Sprintf("max-age=%d", getSmallestTTLFromAnswer(msg)))

	// https://www.rfc-editor.org/rfc/rfc8484#section-4.2.1
	r.rw.WriteHeader(http.StatusOK)

	_, err = r.rw.Write(b)
	if err != nil {
		return fmt.Errorf("failed to write DoH response: %w", err)
	}

	return nil
}

func getSmallestTTLFromAnswer(msg *dns.Msg) uint32 {
	var ttl uint32 = 0
	for _, a := range msg.Answer {
		if a.Header().Ttl < ttl || ttl == 0 {
			ttl = a.Header().Ttl
		}
	}

	return ttl
}

func (s *Server) Query(
	ctx context.Context, serverHost string, clientIP net.IP, question string, qType dns.Type,
) (*model.Response, error) {
	msg := util.NewMsgWithQuestion(question, qType)
	clientID := extractClientIDFromHost(serverHost, s.cfg.ClientGroupEndpoints.Domains)

	ctx, req := newRequest(ctx, clientIP, clientID, model.RequestProtocolTCP, msg)

	return s.resolve(ctx, req)
}

type discoveredClient struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname,omitempty"`
	Device   string `json:"device"`
}

func handleDiscoveredClients(w http.ResponseWriter, r *http.Request) {
	entries, err := arp.Read()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	clients := make([]discoveredClient, 0, len(entries))

	for _, e := range entries {
		c := discoveredClient{
			IP:     e.IP,
			MAC:    e.MAC,
			Device: e.Device,
		}

		// Best-effort reverse DNS lookup
		names, err := net.LookupAddr(e.IP)
		if err == nil && len(names) > 0 {
			c.Hostname = names[0]
		}

		clients = append(clients, c)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(clients)
}

// registerUIRoutes adds all admin routes: API, config, UI, static assets,
// docs, debug, metrics, websocket logs. Does NOT add DoH endpoints — those
// are registered on the outer router by the caller in combined-port mode or
// on a separate DoH-only router in split-port mode.
//
// Route-shape rules:
//
//   - Prometheus metrics and mobileconfig are mounted on the outer router,
//     outside the auth group, because they are scraped or fetched without
//     session cookies (monitoring, MDM provisioning).
//   - DoH is never mounted here — see the caller.
//   - Everything else (API, config, UI, static, docs, websocket) goes behind
//     RequireAuth + RequireCSRFHeader. Mutating API routes are further gated by
//     RequireAdminForMutations so `viewer` users are read-only.
//   - pprof/expvar is NOT here. RequireAuth only rejects /api/* paths, so a
//     /debug group on this router would be readable without a session; it lives
//     on its own loopback listener instead (server/server_debug.go).
func registerUIRoutes(router *chi.Mux, cfg *config.Config,
	openAPIImpl api.StrictServerInterface,
	store *configstore.ConfigStore, reconfigurer configapi.Reconfigurer,
	broadcaster *logstream.Broadcaster,
	statsCollector *statscollector.Collector,
	revoker *auth.WSRevoker,
) {
	// --- Public (no auth ever) ---

	// Prometheus metrics — scraped by monitoring without auth.
	// Healthcheck for k8s/load-balancers is implemented via DNS
	// (healthcheck.blocky, see server.go:registerDNSHandlers), not HTTP —
	// no HTTP healthcheck endpoint exists here, so nothing further to
	// exclude from the auth group for probe access.
	metrics.Start(router, cfg.Prometheus)

	// Mobileconfig downloads (public by design — consumed by MDM/Apple
	// Configurator which cannot carry a session cookie).
	if store != nil {
		router.Get("/api/mobileconfig/{slug}", handleMobileconfig(cfg, store))
	}

	// Public auth endpoints (login + first-run setup).
	// CSRF is applied internally by RegisterPublicRoutes.
	if store != nil {
		registerAuthRoutes(router, store)
	}

	// --- Authenticated group ---
	router.Group(func(r chi.Router) {
		if store != nil {
			r.Use(auth.RequireAuth(store))
			r.Use(auth.RequireCSRFHeader())
		}

		// Auth endpoints that require a session (session probe, logout,
		// password change, users CRUD).
		if store != nil {
			registerAuthenticatedAuthRoutes(r, store)
		}

		// Config & stats & existing OpenAPI routes (admin-only for mutations).
		r.Group(func(r chi.Router) {
			if store != nil {
				r.Use(auth.RequireAdminForMutations())
			}

			// Existing OpenAPI operations: /api/blocking/*, /api/cache/flush,
			// /api/lists/refresh, /api/query. All are admin-guarded for
			// mutations via RequireAdminForMutations; the read-only
			// /api/blocking/status passes through for viewer users.
			api.RegisterOpenAPIEndpoints(r, openAPIImpl)

			if store != nil {
				configapi.RegisterEndpoints(r, configapi.NewConfigHandler(store, reconfigurer))
			}

			r.Get("/api/discovered-clients", handleDiscoveredClients)
			r.Get("/api/endpoint-info", handleEndpointInfo(cfg))
			r.Get("/api/stats", handleStats)
			r.Get("/api/stats/overtime", handleStatsOvertime(statsCollector))
			r.Get("/api/stats/overtime/clients", handleStatsOvertimeClients(statsCollector))
			r.Get("/api/stats/overtime/latency", handleStatsOvertimeLatency(statsCollector))
			r.Get("/api/stats/query-types", handleStatsQueryTypes(statsCollector))
			r.Get("/api/stats/response-types", handleStatsResponseTypes(statsCollector))
			r.Get("/api/stats/top-domains", handleStatsTopDomains(statsCollector))
			r.Get("/api/stats/top-clients", handleStatsTopClients(statsCollector))
			r.Get("/api/version", handleVersion)
		})

		if broadcaster != nil {
			r.Get("/api/ws/logs", wsLogsHandler(broadcaster, revoker))
		}

		configureDocsHandler(r)
		configureStaticAssetsHandler(r)
		configureUIHandler(r)
		configureRootHandler(cfg, r)
		configureRobotsHandler(r)
	})
}

func createHTTPRouter(cfg *config.Config, openAPIImpl api.StrictServerInterface,
	store *configstore.ConfigStore, reconfigurer configapi.Reconfigurer,
	broadcaster *logstream.Broadcaster,
	statsCollector *statscollector.Collector,
	revoker *auth.WSRevoker,
) *chi.Mux {
	router := chi.NewRouter()

	registerUIRoutes(router, cfg, openAPIImpl, store, reconfigurer, broadcaster, statsCollector, revoker)

	return router
}

func configureDocsHandler(router chi.Router) {
	router.Get("/docs/openapi.yaml", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(contentTypeHeader, yamlContentType)
		_, err := writer.Write([]byte(docs.OpenAPI))
		logAndResponseWithError(err, "can't write OpenAPI definition file: ", writer)
	})

	router.Get("/docs/config.schema.json", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(contentTypeHeader, jsonContentType)
		_, err := writer.Write(docs.ConfigSchema)
		logAndResponseWithError(err, "can't write config JSON schema file: ", writer)
	})
}

func configureStaticAssetsHandler(router chi.Router) {
	assets, err := web.Assets()
	util.FatalOnError("unable to load static asset files", err)

	fs := http.FileServer(http.FS(assets))
	router.Handle("/static/*", http.StripPrefix("/static/", fs))
}

func configureUIHandler(router chi.Router) {
	uiAssets, err := web.UIAssets()
	if err != nil {
		logger().Warn("UI assets not available: ", err)

		return
	}

	uiFS := http.FileServer(http.FS(uiAssets))
	router.Handle("/ui/*", http.StripPrefix("/ui/", uiFS))
	router.Get("/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusMovedPermanently)
	})
}

func configureRobotsHandler(router chi.Router) {
	router.Handle("/robots.txt", http.FileServer(http.FS(web.WebFs)))
}

func configureRootHandler(cfg *config.Config, router chi.Router) {
	router.Get("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(contentTypeHeader, htmlContentType)

		t := template.New("index")

		_, _ = t.Parse(web.IndexTmpl)

		type HandlerLink struct {
			URL     string
			Title   string
			Icon    string
			Primary bool
		}

		type PageData struct {
			Links     []HandlerLink
			Version   string
			BuildTime string
		}

		pd := PageData{
			Version:   util.Version,
			BuildTime: util.BuildTime,
			Links: []HandlerLink{
				{URL: "/ui/", Title: "Web UI", Icon: "◆", Primary: true},
				{URL: "/docs/openapi.yaml", Title: "REST API docs (OpenAPI)", Icon: "○"},
				{URL: "/static/rapidoc.html", Title: "Interactive API explorer", Icon: "⚙"},
				{URL: "/docs/config.schema.json", Title: "Configuration JSON Schema", Icon: "▤"},
			},
		}

		if cfg.Prometheus.Enable {
			pd.Links = append(pd.Links, HandlerLink{
				URL:   cfg.Prometheus.Path,
				Title: "Prometheus metrics",
				Icon:  "☰",
			})
		}

		err := t.Execute(writer, pd)
		logAndResponseWithError(err, "can't write index template: ", writer)
	})
}

func logAndResponseWithError(err error, message string, writer http.ResponseWriter) {
	if err != nil {
		log.Log().Error(message, log.EscapeInput(err.Error()))
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

// wsLogsHandler returns an http.HandlerFunc that upgrades /api/ws/logs to a
// WebSocket and registers the connection with the WSRevoker (when available)
// so it is force-closed on session revocation or at session expiry.
//
// The authenticated user and their current session are pulled from the request
// context (attached by RequireAuth). If no user is attached (should be
// unreachable because this route is mounted inside the authenticated group),
// registration is skipped and the handler still streams — the upstream
// middleware would have rejected an unauthenticated request before reaching
// here.
//
// The revoker's lifetime cap is the session's true ExpiresAt (after any
// sliding-renewal adjustment applied by RequireAuth on this request). The
// proactive revocation path via SessionRevoked → WSRevoker.RevokeUser fires
// immediately regardless of this cap when DeleteSession / ResetPassword /
// DeleteUser runs, which is the critical property the plan requires; the cap
// is the backstop that forces any still-open socket to close at the session's
// own expiry instant even if revocation signals never arrive.
func wsLogsHandler(broadcaster *logstream.Broadcaster, revoker *auth.WSRevoker) http.HandlerFunc {
	if revoker == nil {
		return logstream.Handler(broadcaster)
	}

	hook := func(r *http.Request, conn *websocket.Conn) func() {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			// Defensive: RequireAuth should have already rejected; skip
			// registration rather than register a zero userID.
			return nil
		}

		// Use the real session expiry. Middleware guarantees a session is
		// attached; if it isn't (future refactor bug), fall back to the old
		// conservative cap with a warn log so we don't register a socket
		// with a zero-time deadline that fires immediately.
		var expiresAt time.Time
		if sess := auth.SessionFromContext(r.Context()); sess != nil {
			expiresAt = sess.ExpiresAt
		} else {
			logger().Warn("wsLogsHandler: no session in request context; falling back to SessionDuration cap")

			expiresAt = time.Now().Add(auth.SessionDuration)
		}

		return revoker.Register(user.ID, conn, expiresAt)
	}

	return logstream.HandlerWithHook(broadcaster, hook)
}
