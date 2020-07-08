package resolver

import (
	"blocky/config"
	"blocky/util"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	defaultTimeout = 2 * time.Second
	dnsContentType = "application/dns-message"
)

// UpstreamResolver sends request to external DNS server
type UpstreamResolver struct {
	NextResolver
	upstreamURL    string
	upstreamClient upstreamClient
	net            string
}

type upstreamClient interface {
	callExternal(msg *dns.Msg, upstreamURL string,
		protocol RequestProtocol) (response *dns.Msg, rtt time.Duration, err error)
}

type dnsUpstreamClient struct {
	tcpClient, udpClient *dns.Client
}

type httpUpstreamClient struct {
	client *http.Client
}

func createUpstreamClient(cfg config.Upstream) (client upstreamClient, upstreamURL string) {
	if cfg.Net == config.NetHTTPS {
		return &httpUpstreamClient{
			client: &http.Client{
				Timeout: defaultTimeout,
			},
		}, fmt.Sprintf("%s://%s:%d%s", cfg.Net, cfg.Host, cfg.Port, cfg.Path)
	}

	if cfg.Net == config.NetTCPTLS {
		return &dnsUpstreamClient{
			tcpClient: &dns.Client{
				Net:     cfg.Net,
				Timeout: defaultTimeout,
			},
		}, net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port)))
	}

	// tcp+udp
	return &dnsUpstreamClient{
		tcpClient: &dns.Client{
			Net:     "tcp",
			Timeout: defaultTimeout,
		},
		udpClient: &dns.Client{
			Net:     "udp",
			Timeout: defaultTimeout,
		},
	}, net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port)))
}

func (r *httpUpstreamClient) callExternal(msg *dns.Msg,
	upstreamURL string, protocol RequestProtocol) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	rawDNSMessage, err := msg.Pack()

	if err != nil {
		return nil, 0, fmt.Errorf("can't pack message: %v", err)
	}

	httpResponse, err := r.client.Post(upstreamURL, dnsContentType, bytes.NewReader(rawDNSMessage))

	if err != nil {
		return nil, 0, fmt.Errorf("can't perform https request: %v", err)
	}
	defer httpResponse.Body.Close()

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
	upstreamURL string, protocol RequestProtocol) (response *dns.Msg, rtt time.Duration, err error) {
	if protocol == TCP {
		response, rtt, err = r.tcpClient.Exchange(msg, upstreamURL)
		if err != nil {
			// try UDP as fallback
			if t, ok := err.(*net.OpError); ok {
				if t.Op == "dial" {
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

func NewUpstreamResolver(upstream config.Upstream) *UpstreamResolver {
	upstreamClient, upstreamURL := createUpstreamClient(upstream)

	return &UpstreamResolver{
		upstreamClient: upstreamClient,
		upstreamURL:    upstreamURL,
		net:            upstream.Net}
}

func (r *UpstreamResolver) Configuration() (result []string) {
	return
}

func (r UpstreamResolver) String() string {
	return fmt.Sprintf("upstream '%s:%s'", r.net, r.upstreamURL)
}

func (r *UpstreamResolver) Resolve(request *Request) (response *Response, err error) {
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

			return &Response{Res: resp, Reason: fmt.Sprintf("RESOLVED (%s)", r.upstreamURL)}, err
		}

		if errNet, ok := err.(net.Error); ok && (errNet.Timeout() || errNet.Temporary()) {
			logger.WithField("attempt", attempt).Debugf("Temporary network error / Timeout occurred, retrying...")
			attempt++
		} else {
			return nil, err
		}
	}

	return response, err
}
