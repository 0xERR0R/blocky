package resolver

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	dnsContentType = "application/dns-message"
)

// UpstreamResolver sends request to external DNS server
type UpstreamResolver struct {
	NextResolver
	upstreamURL    string
	upstreamClient upstreamClient
	net            config.NetProtocol
}

type upstreamClient interface {
	callExternal(msg *dns.Msg, upstreamURL string,
		protocol model.RequestProtocol) (response *dns.Msg, rtt time.Duration, err error)
}

type dnsUpstreamClient struct {
	tcpClient, udpClient *dns.Client
}

type httpUpstreamClient struct {
	client *http.Client
}

func createUpstreamClient(cfg config.Upstream) (client upstreamClient, upstreamURL string) {
	if cfg.Net == config.NetProtocolHttps {
		return &httpUpstreamClient{
			client: &http.Client{
				Transport: &http.Transport{
					Dial:                (util.Dialer(config.GetConfig())).Dial,
					TLSHandshakeTimeout: 5 * time.Second,
				},
				Timeout: time.Duration(config.GetConfig().UpstreamTimeout),
			},
		}, fmt.Sprintf("%s://%s:%d%s", cfg.Net, cfg.Host, cfg.Port, cfg.Path)
	}

	if cfg.Net == config.NetProtocolTcpTls {
		return &dnsUpstreamClient{
			tcpClient: &dns.Client{
				Net:     cfg.Net.String(),
				Timeout: time.Duration(config.GetConfig().UpstreamTimeout),
				Dialer:  util.Dialer(config.GetConfig()),
			},
		}, net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port)))
	}

	// tcp+udp
	return &dnsUpstreamClient{
		tcpClient: &dns.Client{
			Net:     "tcp",
			Timeout: time.Duration(config.GetConfig().UpstreamTimeout),
			Dialer:  util.Dialer(config.GetConfig()),
		},
		udpClient: &dns.Client{
			Net:     "udp",
			Timeout: time.Duration(config.GetConfig().UpstreamTimeout),
			Dialer:  util.Dialer(config.GetConfig()),
		},
	}, net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port)))
}

func (r *httpUpstreamClient) callExternal(msg *dns.Msg,
	upstreamURL string, _ model.RequestProtocol) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	rawDNSMessage, err := msg.Pack()

	if err != nil {
		return nil, 0, fmt.Errorf("can't pack message: %w", err)
	}

	httpResponse, err := r.client.Post(upstreamURL, dnsContentType, bytes.NewReader(rawDNSMessage))

	if err != nil {
		return nil, 0, fmt.Errorf("can't perform https request: %w", err)
	}

	defer func() {
		util.LogOnError("cant close response body ", httpResponse.Body.Close())
	}()

	if httpResponse.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("http return code should be %d, but received %d", http.StatusOK, httpResponse.StatusCode)
	}

	contentType := httpResponse.Header.Get("content-type")
	if contentType != dnsContentType {
		return nil, 0, fmt.Errorf("http return content type should be '%s', but was '%s'",
			dnsContentType, contentType)
	}

	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, 0, errors.New("can't read response body")
	}

	response := dns.Msg{}
	err = response.Unpack(body)

	if err != nil {
		return nil, 0, errors.New("can't unpack message")
	}

	return &response, time.Since(start), nil
}

func (r *dnsUpstreamClient) callExternal(msg *dns.Msg,
	upstreamURL string, protocol model.RequestProtocol) (response *dns.Msg, rtt time.Duration, err error) {
	if protocol == model.RequestProtocolTCP {
		response, rtt, err = r.tcpClient.Exchange(msg, upstreamURL)
		if err != nil {
			// try UDP as fallback
			var opErr *net.OpError
			if errors.As(err, &opErr) {
				if opErr.Op == "dial" && r.udpClient != nil {
					return r.udpClient.Exchange(msg, upstreamURL)
				}
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
func NewUpstreamResolver(upstream config.Upstream) *UpstreamResolver {
	upstreamClient, upstreamURL := createUpstreamClient(upstream)

	return &UpstreamResolver{
		upstreamClient: upstreamClient,
		upstreamURL:    upstreamURL,
		net:            upstream.Net}
}

// Configuration return current resolver configuration
func (r *UpstreamResolver) Configuration() (result []string) {
	return
}

func (r UpstreamResolver) String() string {
	return fmt.Sprintf("upstream '%s:%s'", r.net, r.upstreamURL)
}

// Resolve calls external resolver
func (r *UpstreamResolver) Resolve(request *model.Request) (response *model.Response, err error) {
	logger := withPrefix(request.Log, "upstream_resolver")

	attempt := 1

	var rtt time.Duration

	var resp *dns.Msg

	for attempt <= 3 {
		if resp, rtt, err = r.upstreamClient.callExternal(request.Req, r.upstreamURL, request.Protocol); err == nil {
			logger.WithFields(logrus.Fields{
				"answer":           util.AnswerToString(resp.Answer),
				"return_code":      dns.RcodeToString[resp.Rcode],
				"upstream":         r.upstreamURL,
				"protocol":         request.Protocol,
				"net":              r.net,
				"response_time_ms": rtt.Milliseconds(),
			}).Debugf("received response from upstream")

			return &model.Response{Res: resp, Reason: fmt.Sprintf("RESOLVED (%s)", r.upstreamURL)}, nil
		}

		var netErr net.Error
		if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
			logger.WithField("attempt", attempt).Debugf("Temporary network error / Timeout occurred, retrying...")
			attempt++
		} else {
			return nil, err
		}
	}

	return response, err
}
