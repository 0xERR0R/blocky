package resolver

import (
	"bytes"
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

// UpstreamResolver sends request to external DNS server
type UpstreamResolver struct {
	typed

	upstream       config.Upstream
	upstreamClient upstreamClient
	bootstrap      *Bootstrap
}

type upstreamClient interface {
	fmtURL(ip net.IP, port uint16, path string) string
	callExternal(msg *dns.Msg, upstreamURL string,
		protocol model.RequestProtocol) (response *dns.Msg, rtt time.Duration, err error)
}

type dnsUpstreamClient struct {
	tcpClient, udpClient *dns.Client
}

type httpUpstreamClient struct {
	client *http.Client
	host   string
}

func createUpstreamClient(cfg config.Upstream) upstreamClient {
	timeout := config.GetConfig().UpstreamTimeout.ToDuration()

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
			client: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig:     &tlsConfig,
					TLSHandshakeTimeout: defaultTLSHandshakeTimeout,
					ForceAttemptHTTP2:   true,
				},
				Timeout: timeout,
			},
			host: cfg.Host,
		}

	case config.NetProtocolTcpTls:
		return &dnsUpstreamClient{
			tcpClient: &dns.Client{
				TLSConfig:      &tlsConfig,
				Net:            cfg.Net.String(),
				Timeout:        timeout,
				SingleInflight: true,
			},
		}

	case config.NetProtocolTcpUdp:
		return &dnsUpstreamClient{
			tcpClient: &dns.Client{
				Net:            "tcp",
				Timeout:        timeout,
				SingleInflight: true,
			},
			udpClient: &dns.Client{
				Net:            "udp",
				Timeout:        timeout,
				SingleInflight: true,
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

func (r *httpUpstreamClient) callExternal(msg *dns.Msg,
	upstreamURL string, _ model.RequestProtocol,
) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	rawDNSMessage, err := msg.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("can't pack message: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, upstreamURL, bytes.NewReader(rawDNSMessage))
	if err != nil {
		return nil, 0, fmt.Errorf("can't create the new request %w", err)
	}

	req.Header.Set("User-Agent", config.GetConfig().DoHUserAgent)
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

func (r *dnsUpstreamClient) callExternal(msg *dns.Msg,
	upstreamURL string, protocol model.RequestProtocol,
) (response *dns.Msg, rtt time.Duration, err error) {
	if protocol == model.RequestProtocolTCP {
		response, rtt, err = r.tcpClient.Exchange(msg, upstreamURL)
		if err != nil {
			// try UDP as fallback
			var opErr *net.OpError
			if errors.As(err, &opErr) && opErr.Op == "dial" && r.udpClient != nil {
				return r.udpClient.Exchange(msg, upstreamURL)
			}
		}

		return response, rtt, err
	}

	if r.udpClient != nil {
		return r.udpClient.Exchange(msg, upstreamURL)
	}

	return r.tcpClient.Exchange(msg, upstreamURL)
}

// NewUpstreamResolver creates new resolver instance
func NewUpstreamResolver(upstream config.Upstream, bootstrap *Bootstrap, verify bool) (*UpstreamResolver, error) {
	r := newUpstreamResolverUnchecked(upstream, bootstrap)

	if verify {
		_, err := r.bootstrap.UpstreamIPs(r)
		if err != nil {
			return nil, err
		}
	}

	return r, nil
}

// newUpstreamResolverUnchecked creates new resolver instance without validating the upstream
func newUpstreamResolverUnchecked(upstream config.Upstream, bootstrap *Bootstrap) *UpstreamResolver {
	upstreamClient := createUpstreamClient(upstream)

	return &UpstreamResolver{
		typed: withType("upstream"),

		upstream:       upstream,
		upstreamClient: upstreamClient,
		bootstrap:      bootstrap,
	}
}

// IsEnabled implements `config.Configurable`.
func (r *UpstreamResolver) IsEnabled() bool {
	return true
}

// LogConfig implements `config.Configurable`.
func (r *UpstreamResolver) LogConfig(logger *logrus.Entry) {
	logger.Info(r.upstream)
}

func (r UpstreamResolver) String() string {
	return fmt.Sprintf("%s '%s'", r.Type(), r.upstream)
}

// Resolve calls external resolver
func (r *UpstreamResolver) Resolve(request *model.Request) (response *model.Response, err error) {
	ips, err := r.bootstrap.UpstreamIPs(r)
	if err != nil {
		return nil, err
	}

	var (
		rtt  time.Duration
		resp *dns.Msg
		ip   net.IP
	)

	err = retry.Do(
		func() error {
			ip = ips.Current()
			upstreamURL := r.upstreamClient.fmtURL(ip, r.upstream.Port, r.upstream.Path)

			var err error
			resp, rtt, err = r.upstreamClient.callExternal(request.Req, upstreamURL, request.Protocol)
			if err == nil {
				r.log().WithFields(logrus.Fields{
					"answer":           util.AnswerToString(resp.Answer),
					"return_code":      dns.RcodeToString[resp.Rcode],
					"upstream":         r.upstream.String(),
					"upstream_ip":      ip.String(),
					"protocol":         request.Protocol,
					"net":              r.upstream.Net,
					"response_time_ms": rtt.Milliseconds(),
				}).Debugf("received response from upstream")

				return nil
			}

			return fmt.Errorf("can't resolve request via upstream server %s (%s): %w", r.upstream, upstreamURL, err)
		},
		retry.Attempts(retryAttempts),
		retry.DelayType(retry.FixedDelay),
		retry.Delay(1*time.Millisecond),
		retry.LastErrorOnly(true),
		retry.RetryIf(func(err error) bool {
			var netErr net.Error

			return errors.As(err, &netErr) && netErr.Timeout()
		}),
		retry.OnRetry(func(n uint, err error) {
			r.log().WithFields(logrus.Fields{
				"upstream":    r.upstream.String(),
				"upstream_ip": ip.String(),
				"question":    util.QuestionToString(request.Req.Question),
				"attempt":     fmt.Sprintf("%d/%d", n+1, retryAttempts),
			}).Debugf("%s, retrying...", err)

			ips.Next()
		}))
	if err != nil {
		return nil, err
	}

	return &model.Response{Res: resp, Reason: fmt.Sprintf("RESOLVED (%s)", r.upstream)}, nil
}
