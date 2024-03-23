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
	})
})

// Go and cmp don't define func comparisons, besides with nil.
// In practice we can just compare them as pointers.
// See https://github.com/google/go-cmp/issues/162
func cmpAsPtrs[T any](x, y T) bool {
	return reflect.ValueOf(x).Pointer() == reflect.ValueOf(y).Pointer()
}
