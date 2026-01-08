package util

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"reflect"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HTTP Util", func() {
	Describe("DefaultHTTPTransport", func() {
		It("returns a new transport", func() {
			a := DefaultHTTPTransport()
			Expect(a).Should(BeIdenticalTo(a))

			b := DefaultHTTPTransport()
			Expect(a).ShouldNot(BeIdenticalTo(b))
		})

		It("returns a copy of http.DefaultTransport", func() {
			Expect(cmp.Diff(
				DefaultHTTPTransport(), http.DefaultTransport,
				cmpopts.IgnoreUnexported(http.Transport{}),
				// Non nil func field comparers
				cmp.Comparer(cmpAsPtrs[func(context.Context, string, string) (net.Conn, error)]),
				cmp.Comparer(cmpAsPtrs[func(*http.Request) (*url.URL, error)]),
			)).Should(BeEmpty())
		})
	})

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

		It("extracts the first IP from comma-separated X-Forwarded-For header", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			clientIP := net.ParseIP("203.0.113.195")
			proxy1IP := net.ParseIP("70.41.3.18")
			proxy2IP := net.ParseIP("150.172.238.178")

			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("X-Forwarded-For", clientIP.String()+", "+proxy1IP.String()+", "+proxy2IP.String())

			Expect(HTTPClientIP(r)).Should(Equal(clientIP))
		})

		It("extracts the first IP from X-Forwarded-For with extra spaces", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			clientIP := net.ParseIP("203.0.113.195")
			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("X-Forwarded-For", "  "+clientIP.String()+"  , 70.41.3.18 ,  150.172.238.178")

			Expect(HTTPClientIP(r)).Should(Equal(clientIP))
		})

		It("handles IPv6 addresses in X-Forwarded-For", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			clientIP := net.ParseIP("2001:db8:85a3:8d3:1319:8a2e:370:7348")
			proxy1IP := net.ParseIP("2001:db8::1")

			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("X-Forwarded-For", clientIP.String()+", "+proxy1IP.String())

			Expect(HTTPClientIP(r)).Should(Equal(clientIP))
		})

		It("falls back to RemoteAddr when X-Forwarded-For is invalid", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			remoteIP := net.ParseIP("192.168.1.100")
			r.RemoteAddr = net.JoinHostPort(remoteIP.String(), "12345")
			r.Header.Set("X-Forwarded-For", "not-a-valid-ip, also-invalid")

			Expect(HTTPClientIP(r)).Should(Equal(remoteIP))
		})

		It("falls back to RemoteAddr when X-Forwarded-For is empty string", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			remoteIP := net.ParseIP("192.168.1.100")
			r.RemoteAddr = net.JoinHostPort(remoteIP.String(), "12345")
			r.Header.Set("X-Forwarded-For", "")

			Expect(HTTPClientIP(r)).Should(Equal(remoteIP))
		})

		It("handles X-Forwarded-For with only whitespace", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			remoteIP := net.ParseIP("192.168.1.100")
			r.RemoteAddr = net.JoinHostPort(remoteIP.String(), "12345")
			r.Header.Set("X-Forwarded-For", "   ,  , ")

			Expect(HTTPClientIP(r)).Should(Equal(remoteIP))
		})

		// RFC 7239 Forwarded header tests
		It("extracts IP from simple Forwarded header with IPv4", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			clientIP := net.ParseIP("192.0.2.43")
			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("Forwarded", "for="+clientIP.String())

			Expect(HTTPClientIP(r)).Should(Equal(clientIP))
		})

		It("extracts IP from Forwarded header with IPv4 and port", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			clientIP := net.ParseIP("192.0.2.43")
			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("Forwarded", "for=\""+clientIP.String()+":8080\"")

			Expect(HTTPClientIP(r)).Should(Equal(clientIP))
		})

		It("extracts IP from Forwarded header with IPv6 in brackets", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			clientIP := net.ParseIP("2001:db8:cafe::17")
			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("Forwarded", "for=\"["+clientIP.String()+"]\"")

			Expect(HTTPClientIP(r)).Should(Equal(clientIP))
		})

		It("extracts IP from Forwarded header with IPv6 and port", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			clientIP := net.ParseIP("2001:db8:cafe::17")
			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("Forwarded", "for=\"["+clientIP.String()+"]:47011\"")

			Expect(HTTPClientIP(r)).Should(Equal(clientIP))
		})

		It("extracts IP from Forwarded header with multiple parameters", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			clientIP := net.ParseIP("192.0.2.43")
			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("Forwarded", "for="+clientIP.String()+";proto=http;by=203.0.113.43")

			Expect(HTTPClientIP(r)).Should(Equal(clientIP))
		})

		It("extracts first IP from multiple Forwarded entries", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			clientIP := net.ParseIP("192.0.2.60")
			proxy1IP := net.ParseIP("198.51.100.17")
			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("Forwarded", "for="+clientIP.String()+", for="+proxy1IP.String())

			Expect(HTTPClientIP(r)).Should(Equal(clientIP))
		})

		It("skips unknown value in Forwarded header", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			clientIP := net.ParseIP("192.0.2.60")
			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("Forwarded", "for=unknown, for="+clientIP.String())

			Expect(HTTPClientIP(r)).Should(Equal(clientIP))
		})

		It("skips obfuscated identifier in Forwarded header", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			clientIP := net.ParseIP("192.0.2.60")
			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("Forwarded", "for=_hidden, for="+clientIP.String())

			Expect(HTTPClientIP(r)).Should(Equal(clientIP))
		})

		It("prioritizes Forwarded header over X-Forwarded-For", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			forwardedIP := net.ParseIP("192.0.2.43")
			xffIP := net.ParseIP("203.0.113.195")

			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("Forwarded", "for="+forwardedIP.String())
			r.Header.Set("X-Forwarded-For", xffIP.String())

			// Should use Forwarded, not X-Forwarded-For
			Expect(HTTPClientIP(r)).Should(Equal(forwardedIP))
		})

		It("falls back to X-Forwarded-For when Forwarded is invalid", func() {
			r, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			Expect(err).Should(Succeed())

			xffIP := net.ParseIP("203.0.113.195")

			r.RemoteAddr = net.JoinHostPort("192.168.1.1", "12345")
			r.Header.Set("Forwarded", "for=unknown")
			r.Header.Set("X-Forwarded-For", xffIP.String())

			Expect(HTTPClientIP(r)).Should(Equal(xffIP))
		})
	})
})

// Go and cmp don't define func comparisons, besides with nil.
// In practice we can just compare them as pointers.
// See https://github.com/google/go-cmp/issues/162
func cmpAsPtrs[T any](x, y T) bool {
	return reflect.ValueOf(x).Pointer() == reflect.ValueOf(y).Pointer()
}
