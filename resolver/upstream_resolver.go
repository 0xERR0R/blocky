package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
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
	dnsContentType             = "application/dns-message"
	defaultTLSHandshakeTimeout = 5 * time.Second
	retryAttempts              = 3
)

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
	logger.Info(c.Upstream)
}

// UpstreamResolver sends request to external DNS server
type UpstreamResolver struct {
	typed
	configurable[upstreamConfig]

	upstreamClient upstreamClient
	bootstrap      *Bootstrap
}

type upstreamClient interface {
	fmtURL(ip net.IP, port uint16, path string) string
	callExternal(
		ctx context.Context, msg *dns.Msg, upstreamURL string, protocol model.RequestProtocol,
	) (response *dns.Msg, rtt time.Duration, err error)
}

type dnsUpstreamClient struct {
	tcpClient, udpClient *dns.Client
}

type httpUpstreamClient struct {
	client    *http.Client
	host      string
	userAgent string
}

func createUpstreamClient(cfg upstreamConfig) upstreamClient {
	tlsConfig := tls.Config{
		ServerName: cfg.Host,
		MinVersion: tls.VersionTLS12,
	}

	if cfg.CommonName != "" {
		tlsConfig.ServerName = cfg.CommonName
	}

	switch cfg.Net {
	case config.NetProtocolHttps:
		return &httpUpstreamClient{
			userAgent: cfg.UserAgent,
			client: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig:     &tlsConfig,
					TLSHandshakeTimeout: defaultTLSHandshakeTimeout,
					ForceAttemptHTTP2:   true,
				},
			},
			host: cfg.Host,
		}

	case config.NetProtocolTcpTls:
		return &dnsUpstreamClient{
			tcpClient: &dns.Client{
				TLSConfig: &tlsConfig,
				Net:       cfg.Net.String(),
			},
		}

	case config.NetProtocolTcpUdp:
		return &dnsUpstreamClient{
			tcpClient: &dns.Client{
				Net: "tcp",
			},
			udpClient: &dns.Client{
				Net: "udp",
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

func (r *httpUpstreamClient) callExternal(
	ctx context.Context, msg *dns.Msg, upstreamURL string, _ model.RequestProtocol,
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
		util.LogOnError("can't close response body ", httpResponse.Body.Close())
	}()

	if httpResponse.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("http return code should be %d, but received %d", http.StatusOK, httpResponse.StatusCode)
	}

	contentType := httpResponse.Header.Get("content-type")
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

func (r *dnsUpstreamClient) callExternal(
	ctx context.Context, msg *dns.Msg, upstreamURL string, protocol model.RequestProtocol,
) (response *dns.Msg, rtt time.Duration, err error) {
	if protocol == model.RequestProtocolTCP {
		response, rtt, err = r.tcpClient.ExchangeContext(ctx, msg, upstreamURL)
		if err != nil && r.udpClient != nil {
			// try UDP as fallback
			var opErr *net.OpError
			if errors.As(err, &opErr) && opErr.Op == "dial" {
				return r.udpClient.ExchangeContext(ctx, msg, upstreamURL)
			}
		}

		return response, rtt, err
	}

	if r.udpClient != nil {
		return r.udpClient.ExchangeContext(ctx, msg, upstreamURL)
	}

	return r.tcpClient.ExchangeContext(ctx, msg, upstreamURL)
}

// NewUpstreamResolver creates new resolver instance
func NewUpstreamResolver(
	ctx context.Context, cfg upstreamConfig, bootstrap *Bootstrap,
) (*UpstreamResolver, error) {
	r := newUpstreamResolverUnchecked(cfg, bootstrap)

	if cfg.StartVerify {
		_, err := r.bootstrap.UpstreamIPs(ctx, r)
		if err != nil {
			return nil, err
		}
	}

	return r, nil
}

// newUpstreamResolverUnchecked creates new resolver instance without validating the upstream
func newUpstreamResolverUnchecked(cfg upstreamConfig, bootstrap *Bootstrap) *UpstreamResolver {
	upstreamClient := createUpstreamClient(cfg)

	return &UpstreamResolver{
		typed:        withType("upstream"),
		configurable: withConfig(cfg),

		upstreamClient: upstreamClient,
		bootstrap:      bootstrap,
	}
}

func (r UpstreamResolver) String() string {
	return fmt.Sprintf("%s '%s'", r.Type(), r.cfg)
}

func (r *UpstreamResolver) log() *logrus.Entry {
	return r.typed.log().WithField("upstream", r.cfg.String())
}

// testResolve sends a test query to verify the upstream is reachable and working
func (r *UpstreamResolver) testResolve(ctx context.Context) error {
	// example.com MUST always resolve. See SUDN resolver
	request := newRequest("example.com.", dns.Type(dns.TypeA))

	_, err := r.Resolve(ctx, request)

	return err
}

// Resolve calls external resolver
func (r *UpstreamResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	ips, err := r.bootstrap.UpstreamIPs(ctx, r)
	if err != nil {
		return nil, err
	}

	var (
		resp *dns.Msg
		ip   net.IP
	)

	err = retry.Do(
		func() error {
			ip = ips.Current()
			upstreamURL := r.upstreamClient.fmtURL(ip, r.cfg.Port, r.cfg.Path)

			ctx := ctx // make sure we don't overwrite the outer function's context

			if r.cfg.Timeout.IsAboveZero() {
				var cancel context.CancelFunc

				ctx, cancel = context.WithTimeout(ctx, r.cfg.Timeout.ToDuration())
				defer cancel()
			}

			response, rtt, err := r.upstreamClient.callExternal(ctx, request.Req, upstreamURL, request.Protocol)
			if err != nil {
				return fmt.Errorf("can't resolve request via upstream server %s (%s): %w", r.cfg, upstreamURL, err)
			}

			resp = response
			r.logResponse(request, response, ip, rtt)

			return nil
		},
		retry.Context(ctx),
		retry.Attempts(retryAttempts),
		retry.DelayType(retry.FixedDelay),
		retry.Delay(1*time.Millisecond),
		retry.LastErrorOnly(true),
		retry.RetryIf(isTimeout),
		retry.OnRetry(func(n uint, err error) {
			r.log().WithFields(logrus.Fields{
				"upstream":    r.cfg.String(),
				"upstream_ip": ip.String(),
				"question":    util.QuestionToString(request.Req.Question),
				"attempt":     fmt.Sprintf("%d/%d", n+1, retryAttempts),
			}).Debugf("%s, retrying...", err)

			ips.Next()
		}))
	if err != nil {
		return nil, err
	}

	return &model.Response{Res: resp, Reason: fmt.Sprintf("RESOLVED (%s)", r.cfg)}, nil
}

func (r *UpstreamResolver) logResponse(request *model.Request, resp *dns.Msg, ip net.IP, rtt time.Duration) {
	r.log().WithFields(logrus.Fields{
		"answer":           util.AnswerToString(resp.Answer),
		"return_code":      dns.RcodeToString[resp.Rcode],
		"upstream":         r.cfg.String(),
		"upstream_ip":      ip.String(),
		"protocol":         request.Protocol,
		"net":              r.cfg.Net,
		"response_time_ms": rtt.Milliseconds(),
	}).Debugf("received response from upstream")
}

func isTimeout(err error) bool {
	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}
