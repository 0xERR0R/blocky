package resolver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/avast/retry-go/v4"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	dnsContentType       = "application/dns-message"
	upstreamResolverType = "upstream"
	retryAttempts        = 3
	sha256HashLength     = 32

	// connPoolMaxIdle bounds the number of idle DoT connections kept per upstream
	// address, so a burst of concurrent queries can't leak connections.
	connPoolMaxIdle = 8
	// connPoolIdleTimeout discards pooled connections idle longer than this,
	// before an upstream is likely to have closed them.
	connPoolIdleTimeout = 30 * time.Second

	// upstreamUDPBufferFloor is the minimum EDNS0 UDP buffer (bytes) blocky advertises to plain-DNS
	// upstreams, independent of what the client requested. 1232 is the DNS-flag-day-2020 value: big
	// enough to carry most answers without truncation, small enough to avoid IP fragmentation. A
	// shared-cache miss can then fetch the full answer over UDP instead of falling back to TCP.
	upstreamUDPBufferFloor = 1232

	// transport names as understood by dns.Client.Net
	transportTCP = "tcp"
	transportUDP = "udp"
)

// UpstreamServerError wraps a response with RCode ServFail so no other resolver tries to use it.
type UpstreamServerError struct {
	Msg *dns.Msg
}

func (e *UpstreamServerError) Error() string {
	return "upstream server failed"
}

type upstreamConfig struct {
	config.Upstreams
	config.Upstream
}

func newUpstreamConfig(upstream config.Upstream, cfg config.Upstreams) upstreamConfig {
	return upstreamConfig{cfg, upstream}
}

func (c upstreamConfig) String() string {
	return c.Upstream.String()
}

// IsEnabled implements `config.Configurable`.
func (c upstreamConfig) IsEnabled() bool {
	return true
}

// LogConfig implements `config.Configurable`.
func (c upstreamConfig) LogConfig(logger *logrus.Entry) {
	if len(c.CertificateFingerprints) > 0 {
		logger.WithFields(logrus.Fields{
			"cert_pinning":  true,
			"pinned_hashes": len(c.CertificateFingerprints),
		}).Info(c.Upstream)
	} else {
		logger.Info(c.Upstream)
	}
}

// UpstreamResolver sends request to external DNS server
type UpstreamResolver struct {
	typed
	configurable[upstreamConfig]

	upstreamClient upstreamClient
	bootstrap      *Bootstrap
}

type upstreamClient interface {
	io.Closer

	fmtURL(ip net.IP, port uint16, path string) string
	callExternal(
		ctx context.Context, msg *dns.Msg, upstreamURL string,
	) (response *dns.Msg, rtt time.Duration, err error)
}

type dnsUpstreamClient struct {
	tcpClient, udpClient *dns.Client
	// pool reuses persistent connections for the connection-oriented DoT path;
	// nil for the plain tcp+udp client, whose TCP leg is only a rare fallback
	// (truncation, question mismatch, UDP failure) and so does not benefit from
	// pooling.
	pool *connPool
}

type httpUpstreamClient struct {
	client    *http.Client
	host      string
	userAgent string
}

// createCertificatePinningVerifier creates a certificate verifier that validates
// against provided SHA256 hashes from DNS stamp
func createCertificatePinningVerifier(
	pinnedHashes []config.CertificateFingerprint,
) func([][]byte, [][]*x509.Certificate) error {
	// Pre-filter hashes to only include valid SHA-256 hashes (32 bytes)
	validHashes := make([][]byte, 0, len(pinnedHashes))
	for _, h := range pinnedHashes {
		if len(h) == sha256HashLength {
			validHashes = append(validHashes, []byte(h))
		}
	}

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// If no verified chains, fail
		if len(verifiedChains) == 0 {
			return errors.New("no verified certificate chains")
		}

		// Count total certificates for better error message
		certCount := 0

		// Check each certificate in the chain
		for _, chain := range verifiedChains {
			for _, cert := range chain {
				certCount++
				certHash := sha256.Sum256(cert.RawTBSCertificate)

				// Check if this certificate matches any pinned hash
				for _, pinnedHash := range validHashes {
					// Use constant-time comparison to prevent timing attacks
					if subtle.ConstantTimeCompare(certHash[:], pinnedHash) == 1 {
						// Match found! Certificate is pinned
						return nil
					}
				}
			}
		}

		// No matching certificate found in any chain
		return fmt.Errorf(
			"certificate pinning failed: checked %d certificates across %d chains, none matched %d pinned hashes "+
				"(server certificate may have rotated - try updating DNS stamp)",
			certCount, len(verifiedChains), len(validHashes),
		)
	}
}

func createUpstreamClient(cfg upstreamConfig) upstreamClient {
	tlsConfig := tls.Config{
		ServerName: cfg.Host,
		MinVersion: tls.VersionTLS12,
	}

	// Use ProviderName from DNS stamp if available (stored in CommonName)
	if cfg.CommonName != "" {
		tlsConfig.ServerName = cfg.CommonName
	}

	// Add certificate pinning if hashes are provided from DNS stamp
	certPinning := len(cfg.CertificateFingerprints) > 0
	if certPinning {
		tlsConfig.VerifyPeerCertificate = createCertificatePinningVerifier(cfg.CertificateFingerprints) //nolint:gosec
	}

	// Enable TLS session resumption for all TLS-based protocols (DoH, DoT, DoQ) so
	// reconnections skip the full handshake. Not when a certificate is pinned: Go
	// does not call VerifyPeerCertificate (our pinning check) on resumed sessions,
	// so resumption would bypass the pin. (The plain tcp+udp client ignores tlsConfig.)
	if !certPinning {
		tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	}

	switch cfg.Net {
	case config.NetProtocolHttps:
		transport := util.DefaultHTTPTransport()
		transport.TLSClientConfig = &tlsConfig

		return &httpUpstreamClient{
			userAgent: cfg.UserAgent,
			client: &http.Client{
				Transport: transport,
			},
			host: cfg.Host,
		}

	case config.NetProtocolTcpTls:
		tcpClient := &dns.Client{
			TLSConfig: &tlsConfig,
			Net:       cfg.Net.String(),
		}

		return &dnsUpstreamClient{
			tcpClient: tcpClient,
			pool:      newConnPool(tcpClient, connPoolMaxIdle, connPoolIdleTimeout),
		}

	case config.NetProtocolQuic:
		return newQuicUpstreamClient(&tlsConfig, cfg.QUIC)

	case config.NetProtocolTcpUdp:
		return &dnsUpstreamClient{
			tcpClient: &dns.Client{
				Net: transportTCP,
			},
			udpClient: &dns.Client{
				Net: transportUDP,
			},
		}

	default:
		log.Log().Fatalf("invalid protocol %s", cfg.Net)
		panic("unreachable")
	}
}

func (r *httpUpstreamClient) fmtURL(ip net.IP, port uint16, path string) string {
	return fmt.Sprintf("https://%s%s", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), path)
}

// Close releases idle keep-alive connections. Implements io.Closer.
func (r *httpUpstreamClient) Close() error {
	r.client.CloseIdleConnections()

	return nil
}

func (r *httpUpstreamClient) callExternal(
	ctx context.Context, msg *dns.Msg, upstreamURL string,
) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	rawDNSMessage, err := msg.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("can't pack message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(rawDNSMessage))
	if err != nil {
		return nil, 0, fmt.Errorf("can't create the new request %w", err)
	}

	req.Header.Set("User-Agent", r.userAgent)
	req.Header.Set("Content-Type", dnsContentType)
	req.Host = r.host

	httpResponse, err := r.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("can't perform https request: %w", err)
	}

	defer func() {
		// Drain body before closing to allow connection reuse
		// See: https://pkg.go.dev/net/http#Response.Body
		_, _ = io.Copy(io.Discard, httpResponse.Body)
		util.LogOnError(ctx, "can't close response body ", httpResponse.Body.Close())
	}()

	if httpResponse.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("http return code should be %d, but received %d", http.StatusOK, httpResponse.StatusCode)
	}

	contentType := httpResponse.Header.Get("Content-Type")
	if contentType != dnsContentType {
		return nil, 0, fmt.Errorf("http return content type should be '%s', but was '%s'",
			dnsContentType, contentType)
	}

	body, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("can't read response body:  %w", err)
	}

	response := dns.Msg{}
	err = response.Unpack(body)
	if err != nil {
		return nil, 0, fmt.Errorf("can't unpack message: %w", err)
	}

	return &response, time.Since(start), nil
}

func (r *dnsUpstreamClient) fmtURL(ip net.IP, port uint16, _ string) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

// Close releases the connection pool's idle connections, if pooling is in use
// (the DoT path). Implements io.Closer.
func (r *dnsUpstreamClient) Close() error {
	if r.pool != nil {
		return r.pool.Close()
	}

	return nil
}

func (r *dnsUpstreamClient) callExternal(
	ctx context.Context, msg *dns.Msg, upstreamURL string,
) (response *dns.Msg, rtt time.Duration, err error) {
	if r.udpClient == nil {
		// Single connection-oriented client (DoT): reuse pooled connections when a
		// pool is configured, otherwise fall back to a one-shot exchange rather than
		// dereferencing a nil pool.
		var (
			resp *dns.Msg
			rtt  time.Duration
			err  error
		)

		if r.pool != nil {
			resp, rtt, err = r.pool.exchange(ctx, msg, upstreamURL)
		} else {
			resp, rtt, err = r.tcpClient.ExchangeContext(ctx, msg, upstreamURL)
		}

		if err != nil {
			return nil, 0, fmt.Errorf("TCP DNS exchange failed to %s: %w", upstreamURL, err)
		}

		return resp, rtt, servFailToError(resp)
	}

	return r.exchangeUDPWithTCPFallback(ctx, msg, upstreamURL)
}

// servFailToError returns an UpstreamServerError if resp is a SERVFAIL, so no other resolver tries
// to reuse the response; nil otherwise.
func servFailToError(resp *dns.Msg) error {
	if resp.Rcode == dns.RcodeServerFailure {
		return &UpstreamServerError{resp}
	}

	return nil
}

// exchange performs a single DNS exchange and maps an upstream SERVFAIL to an UpstreamServerError.
func (r *dnsUpstreamClient) exchange(
	ctx context.Context, client *dns.Client, msg *dns.Msg, upstreamURL string,
) (*dns.Msg, time.Duration, error) {
	resp, rtt, err := client.ExchangeContext(ctx, msg, upstreamURL)
	if err == nil {
		err = servFailToError(resp)
	}

	return resp, rtt, err
}

// exchangeUDPWithTCPFallback queries the upstream over UDP first and only re-queries over TCP when
// the UDP exchange failed (timeout, network error, SERVFAIL — e.g. UDP/53 blocked while TCP still
// works) or its answer can't be used as-is: it is truncated (TC bit) or its question section doesn't
// match the request. UDP serves the vast majority of queries, so this avoids opening a TCP
// connection — and paying its dial/handshake/goroutine cost — on the common path. The UDP query
// advertises an EDNS0 buffer floor (see udpRequestWithBufferFloor) so larger answers arrive over UDP
// rather than forcing the TCP fallback.
//
// Note the UDP exchange shares the per-attempt context deadline with the fallback: if UDP fails by
// timing out, the TCP fallback inherits an (almost) expired context and fails immediately, and the
// retry in Resolve takes over. The fallback helps when UDP fails fast (e.g. ICMP port unreachable).
func (r *dnsUpstreamClient) exchangeUDPWithTCPFallback(
	ctx context.Context, msg *dns.Msg, upstreamURL string,
) (*dns.Msg, time.Duration, error) {
	resp, rtt, err := r.exchange(ctx, r.udpClient, udpRequestWithBufferFloor(msg), upstreamURL)

	switch {
	case err != nil:
		// Hard UDP failure (timeout, network error, SERVFAIL): re-ask over TCP, which may still work
		// on networks where UDP/53 is blocked or dropped. On TCP failure, return the UDP result —
		// it's the primary transport, so its error is the more representative one.
		tcpResp, tcpRTT, tcpErr := r.exchange(ctx, r.tcpClient, msg, upstreamURL)
		if tcpErr != nil {
			return resp, rtt, err
		}

		resp, rtt = tcpResp, tcpRTT

	case resp.Truncated:
		// Re-ask over TCP, which has no size limit. The original request is sent so we don't
		// advertise an EDNS0 buffer the client never asked for over the TCP hop.
		if tcpResp, tcpRTT, tcpErr := r.exchange(ctx, r.tcpClient, msg, upstreamURL); tcpErr == nil {
			resp, rtt = tcpResp, tcpRTT
		}
		// On TCP failure we keep the truncated UDP answer: it is a valid (partial) answer for the
		// right question, and the downstream `Server` sets the TC bit if it is too big for the
		// client's transport.

	case !responseMatchesRequest(msg, resp):
		// The UDP answer can't be trusted at all, so unlike the truncated case it must not be
		// returned: a TCP failure here fails the whole exchange.
		tcpResp, tcpRTT, tcpErr := r.exchange(ctx, r.tcpClient, msg, upstreamURL)
		if tcpErr != nil {
			return nil, 0, fmt.Errorf(
				"UDP response question section doesn't match the request and TCP fallback failed: %w", tcpErr)
		}

		resp, rtt = tcpResp, tcpRTT
	}

	if msg.IsEdns0() == nil {
		// We may have advertised the EDNS0 buffer floor the client never asked for; don't leak the
		// resulting OPT record back to a client that didn't request EDNS0.
		util.RemoveEdns0Record(resp)
	}

	return resp, rtt, nil
}

// udpRequestWithBufferFloor returns the message to send to an upstream over UDP, ensuring it
// advertises an EDNS0 UDP buffer of at least upstreamUDPBufferFloor. If msg already advertises
// enough it is returned unchanged; otherwise a copy with a raised (or newly added) OPT is returned,
// so the caller's shared request — which also drives per-client response truncation in the Server —
// is never mutated.
func udpRequestWithBufferFloor(msg *dns.Msg) *dns.Msg {
	if opt := msg.IsEdns0(); opt != nil && opt.UDPSize() >= upstreamUDPBufferFloor {
		return msg
	}

	clone := msg.Copy()
	if opt := clone.IsEdns0(); opt != nil {
		// raise the existing OPT in place so its options and DO bit are kept
		opt.SetUDPSize(upstreamUDPBufferFloor)
	} else {
		clone.SetEdns0(upstreamUDPBufferFloor, false)
	}

	return clone
}

// responseMatchesRequest reports whether resp can be trusted as an answer to req: its question
// section must be empty — servers commonly omit it on error rcodes such as REFUSED — or contain the
// same questions, each with a matching type, class, and (case-insensitive) name. A question for
// something else indicates a buggy or confused upstream whose UDP answer can't be trusted, so the
// caller re-asks over TCP.
func responseMatchesRequest(req, resp *dns.Msg) bool {
	if len(resp.Question) == 0 {
		return true
	}

	if len(resp.Question) != len(req.Question) {
		return false
	}

	for i := range req.Question {
		q, rq := req.Question[i], resp.Question[i]
		if rq.Qtype != q.Qtype || rq.Qclass != q.Qclass || !strings.EqualFold(rq.Name, q.Name) {
			return false
		}
	}

	return true
}

// NewUpstreamResolver creates new resolver instance
func NewUpstreamResolver(
	ctx context.Context, cfg upstreamConfig, bootstrap *Bootstrap,
) (*UpstreamResolver, error) {
	r := newUpstreamResolverUnchecked(cfg, bootstrap)

	onErr := func(err error) {
		_, logger := r.log(ctx)

		logger.WithError(err).Warn("initial resolver test failed")
	}

	err := cfg.Init.Strategy.Do(ctx, r.testResolve, onErr)
	if err != nil {
		return nil, fmt.Errorf("upstream %s failed initialization test: %w", cfg.String(), err)
	}

	return r, nil
}

// newUpstreamResolverUnchecked creates new resolver instance without validating the upstream
func newUpstreamResolverUnchecked(cfg upstreamConfig, bootstrap *Bootstrap) *UpstreamResolver {
	upstreamClient := createUpstreamClient(cfg)

	return &UpstreamResolver{
		typed:        withType(upstreamResolverType),
		configurable: withConfig(cfg),

		upstreamClient: upstreamClient,
		bootstrap:      bootstrap,
	}
}

func (r UpstreamResolver) String() string {
	return fmt.Sprintf("%s '%s'", r.Type(), r.cfg)
}

func (r UpstreamResolver) Upstream() config.Upstream {
	return r.cfg.Upstream
}

func (r *UpstreamResolver) log(ctx context.Context) (context.Context, *logrus.Entry) {
	return r.logWithFields(ctx, logrus.Fields{
		logFieldUpstream: r.cfg.String(),
	})
}

// testResolve sends a test query to verify the upstream is reachable and working
func (r *UpstreamResolver) testResolve(ctx context.Context) error {
	// example.com MUST always resolve. See SUDN resolver
	request := newRequest(exampleDomain, dns.Type(dns.TypeA))

	_, err := r.Resolve(ctx, request)
	if err != nil {
		return fmt.Errorf("test query to example.com failed: %w", err)
	}

	return nil
}

// Resolve calls external resolver
func (r *UpstreamResolver) Resolve(ctx context.Context, request *model.Request) (response *model.Response, err error) {
	ctx, logger := r.log(ctx)

	ips, err := r.bootstrap.UpstreamIPs(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve upstream IPs for %s: %w", r.cfg.String(), err)
	}

	var (
		resp *dns.Msg
		ip   net.IP
	)

	err = retry.Do(
		func() error {
			ip = ips.Current()
			upstreamURL := r.upstreamClient.fmtURL(ip, r.cfg.Port, r.cfg.Path)

			ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout.ToDuration())
			defer cancel()

			response, rtt, err := r.upstreamClient.callExternal(ctx, request.Req, upstreamURL)
			if err != nil {
				return fmt.Errorf("can't resolve request via upstream server %s (%s): %w", r.cfg, upstreamURL, err)
			}

			resp = response
			r.logResponse(logger, request, response, ip, rtt)

			return nil
		},
		retry.Context(ctx),
		retry.Attempts(retryAttempts),
		retry.DelayType(retry.FixedDelay),
		retry.Delay(1*time.Millisecond),
		retry.LastErrorOnly(true),
		retry.RetryIf(isTimeout),
		retry.OnRetry(func(n uint, err error) {
			logger.WithFields(logrus.Fields{
				logFieldUpstream: r.cfg.String(),
				"upstream_ip":    ip.String(),
				"question":       util.QuestionToString(request.Req.Question),
				"attempt":        fmt.Sprintf("%d/%d", n+1, retryAttempts),
			}).Debugf("%s, retrying...", err)

			ips.Next()
		}))
	if err != nil {
		return nil, fmt.Errorf("all %d attempts to resolve via upstream %s failed: %w", retryAttempts, r.cfg.String(), err)
	}

	return &model.Response{Res: resp, Reason: fmt.Sprintf("RESOLVED (%s)", r.cfg)}, nil
}

func (r *UpstreamResolver) logResponse(
	logger *logrus.Entry, request *model.Request, resp *dns.Msg, ip net.IP, rtt time.Duration,
) {
	// runs on every successful upstream response (every cache miss); skip building the
	// (expensive) answer string / field map entirely when Debug isn't enabled.
	if !logger.Logger.IsLevelEnabled(logrus.DebugLevel) {
		return
	}

	logger.WithFields(logrus.Fields{
		logFieldAnswer:     util.Obfuscate(util.AnswerToString(resp.Answer)),
		"return_code":      dns.RcodeToString[resp.Rcode],
		logFieldUpstream:   r.cfg.String(),
		"upstream_ip":      ip.String(),
		logFieldProtocol:   request.Protocol,
		"net":              r.cfg.Net,
		"response_time_ms": rtt.Milliseconds(),
	}).Debugf("received response from upstream")
}

func isTimeout(err error) bool {
	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}
