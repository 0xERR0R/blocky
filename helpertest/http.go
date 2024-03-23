package helpertest

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"

	"github.com/onsi/ginkgo/v2"
)

type HTTPProxy struct {
	Addr          net.Addr
	requestTarget atomic.Value // string: HTTP Host of latest request
}

// TestHTTPProxy returns a new HTTPProxy server.
//
// All requests return http.StatusNotImplemented.
func TestHTTPProxy() *HTTPProxy {
	proxyListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		ginkgo.Fail(fmt.Sprintf("could not create HTTP proxy listener: %s", err))
	}

	proxy := &HTTPProxy{
		Addr: proxyListener.Addr(),
	}

	proxySrv := http.Server{ //nolint:gosec
		Addr:    "127.0.0.1:0",
		Handler: proxy,
	}

	go func() { _ = proxySrv.Serve(proxyListener) }()
	ginkgo.DeferCleanup(proxySrv.Close)

	return proxy
}

// URL returns the proxy's URL for use by clients.
func (p *HTTPProxy) URL() *url.URL {
	return &url.URL{
		Scheme: "http",
		Host:   p.Addr.String(),
	}
}

// Check ReqURL has the right type signature for http.Transport.Proxy
var _ = http.Transport{Proxy: (*HTTPProxy)(nil).ReqURL}

func (p *HTTPProxy) ReqURL(*http.Request) (*url.URL, error) {
	return p.URL(), nil
}

// RequestTarget returns the target of the last request.
func (p *HTTPProxy) RequestTarget() string {
	val := p.requestTarget.Load()
	if val == nil {
		ginkgo.Fail(fmt.Sprintf("http proxy %s received no requests", p.Addr))
	}

	return val.(string)
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	p.requestTarget.Store(req.Host)

	w.WriteHeader(http.StatusNotImplemented)
}
