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

// parseForwardedHeader parses RFC 7239 Forwarded header and extracts the client IP
// Format: for=192.0.2.43;proto=http;by=203.0.113.43
// Or multiple: for=192.0.2.43, for=192.0.2.60
func parseForwardedHeader(forwarded string) net.IP {
	// Split by comma to get individual forwarded elements
	elements := splitCommaSeparated(forwarded)

	for _, element := range elements {
		// Split by semicolon to get parameters (for, by, proto, host)
		params := strings.Split(element, ";")

		for _, param := range params {
			param = strings.TrimSpace(param)

			// Look for "for=" parameter
			if !strings.HasPrefix(param, "for=") {
				continue
			}

			// Extract value after "for="
			value := strings.TrimPrefix(param, "for=")

			// Strip quotes if present
			value = strings.Trim(value, "\"")

			// Skip special values
			if value == "unknown" || strings.HasPrefix(value, "_") {
				continue
			}

			// Extract IP from value (may include port and/or brackets)
			if ip := extractIPFromForValue(value); ip != nil {
				return ip
			}
		}
	}

	return nil
}

// extractIPFromForValue extracts IP from Forwarded header "for" parameter value
// Handles: 192.0.2.43, 192.0.2.43:8080, [2001:db8::1], [2001:db8::1]:8080
func extractIPFromForValue(value string) net.IP {
	// Handle IPv6 with brackets: [2001:db8::1] or [2001:db8::1]:8080
	if strings.HasPrefix(value, "[") {
		// Find closing bracket
		closeBracket := strings.Index(value, "]")
		if closeBracket > 0 {
			// Extract IP between brackets
			ipStr := value[1:closeBracket]

			return net.ParseIP(ipStr)
		}
	}

	// Handle IPv4 or IPv4:port
	// For IPv4 with port, split on last colon
	if strings.Contains(value, ":") {
		// Split on last colon to handle port
		lastColon := strings.LastIndex(value, ":")
		ipStr := value[:lastColon]

		return net.ParseIP(ipStr)
	}

	// Plain IP without port or brackets
	return net.ParseIP(value)
}

func HTTPClientIP(r *http.Request) net.IP {
	// Try RFC 7239 Forwarded header first (standardized)
	if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
		if ip := parseForwardedHeader(forwarded); ip != nil {
			return ip
		}
	}

	// Try X-Forwarded-For header (de facto standard)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
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
