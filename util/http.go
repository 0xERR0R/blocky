package util

import (
	"fmt"
	"net"
	"net/http"
)

//nolint:gochecknoglobals
var baseTransport *http.Transport

//nolint:gochecknoinits
func init() {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		panic(fmt.Errorf(
			"unsupported Go version: http.DefaultTransport is not of type *http.Transport: it is a %T",
			http.DefaultTransport,
		))
	}

	baseTransport = base
}

// DefaultHTTPTransport returns a new Transport with the same defaults as net/http.
func DefaultHTTPTransport() *http.Transport {
	return &http.Transport{
		Dial:                   baseTransport.Dial, //nolint:staticcheck
		DialContext:            baseTransport.DialContext,
		DialTLS:                baseTransport.DialTLS, //nolint:staticcheck
		DialTLSContext:         baseTransport.DialTLSContext,
		DisableCompression:     baseTransport.DisableCompression,
		DisableKeepAlives:      baseTransport.DisableKeepAlives,
		ExpectContinueTimeout:  baseTransport.ExpectContinueTimeout,
		ForceAttemptHTTP2:      baseTransport.ForceAttemptHTTP2,
		GetProxyConnectHeader:  baseTransport.GetProxyConnectHeader,
		IdleConnTimeout:        baseTransport.IdleConnTimeout,
		MaxConnsPerHost:        baseTransport.MaxConnsPerHost,
		MaxIdleConns:           baseTransport.MaxIdleConns,
		MaxIdleConnsPerHost:    baseTransport.MaxConnsPerHost,
		MaxResponseHeaderBytes: baseTransport.MaxResponseHeaderBytes,
		OnProxyConnectResponse: baseTransport.OnProxyConnectResponse,
		Proxy:                  baseTransport.Proxy,
		ProxyConnectHeader:     baseTransport.ProxyConnectHeader,
		ReadBufferSize:         baseTransport.ReadBufferSize,
		ResponseHeaderTimeout:  baseTransport.ResponseHeaderTimeout,
		TLSClientConfig:        baseTransport.TLSClientConfig,
		TLSHandshakeTimeout:    baseTransport.TLSHandshakeTimeout,
		TLSNextProto:           baseTransport.TLSNextProto,
		WriteBufferSize:        baseTransport.WriteBufferSize,
	}
}

func HTTPClientIP(r *http.Request) net.IP {
	addr := r.Header.Get("X-FORWARDED-FOR")
	if addr == "" {
		addr = r.RemoteAddr
	}

	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.ParseIP(addr)
	}

	return net.ParseIP(ip)
}
