package util

import (
	"net"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HTTP Util", func() {
	Describe("HTTPClientIP", func() {
		It("extracts the IP from RemoteAddr", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			ip := net.IPv4allrouter
			r.RemoteAddr = net.JoinHostPort(ip.String(), "78954")

			Expect(HTTPClientIP(r)).Should(Equal(ip))
		})

		It("extracts the IP from RemoteAddr without a port", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			ip := net.IPv4allrouter
			r.RemoteAddr = ip.String()

			Expect(HTTPClientIP(r)).Should(Equal(ip))
		})

		It("extracts the IP from the X-Forwarded-For header", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			ip := net.IPv4bcast
			r.RemoteAddr = ip.String()

			r.Header.Set("X-Forwarded-For", ip.String())

			Expect(HTTPClientIP(r)).Should(Equal(ip))
		})
	})
})
