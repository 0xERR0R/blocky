package util

import (
	"net"
	"net/http"
)

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
