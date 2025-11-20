package util

import (
	"fmt"
	"net"
	"net/http"
	"strings"
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
		DialContext:            baseTransport.DialContext,
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

// splitCommaSeparated splits a comma-separated string and trims whitespace from each part
func splitCommaSeparated(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

func HTTPClientIP(r *http.Request) net.IP {
	// Try X-Forwarded-For header first (used when behind reverse proxy)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For format: "<client>, <proxy1>, <proxy2>, ..."
		// The leftmost IP is the original client
		ips := splitCommaSeparated(xff)
		if len(ips) > 0 {
			// Parse the first IP (original client)
			if ip := net.ParseIP(ips[0]); ip != nil {
				return ip
			}
		}
	}

	// Fallback to RemoteAddr (format: "host:port")
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr might not have a port in some cases
		return net.ParseIP(r.RemoteAddr)
	}

	return net.ParseIP(ip)
}
