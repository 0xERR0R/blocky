package server

import (
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HTTP middleware", func() {
	var handler http.Handler

	BeforeEach(func() {
		handler = withCommonMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	})

	Describe("CORS", func() {
		preflight := func(headers map[string]string) *http.Response {
			req := httptest.NewRequest(http.MethodOptions, "/api/blocking/disable", nil)
			req.Header.Set("Origin", "https://grafana.example.com")
			req.Header.Set("Access-Control-Request-Method", http.MethodGet)

			for k, v := range headers {
				req.Header.Set(k, v)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			return rec.Result()
		}

		It("should answer a cross-origin preflight", func() {
			res := preflight(nil)

			Expect(res.Header.Get("Access-Control-Allow-Origin")).Should(Equal("*"))
			Expect(res.Header.Get("Access-Control-Allow-Methods")).Should(ContainSubstring(http.MethodGet))
		})

		It("should allow preflights requesting arbitrary headers", func() {
			// Web UIs send tool-specific headers, e.g. Grafana action buttons
			// always add 'X-Grafana-Action'. A disallowed header makes the
			// middleware answer the preflight without any CORS headers, so the
			// browser blocks the request.
			res := preflight(map[string]string{
				"Access-Control-Request-Headers": "content-type,x-grafana-action",
			})

			Expect(res.Header.Get("Access-Control-Allow-Origin")).Should(Equal("*"))
			// rs/cors answers a wildcard allowlist by echoing the requested headers
			Expect(res.Header.Get("Access-Control-Allow-Headers")).Should(ContainSubstring("x-grafana-action"))
		})

		It("should allow Private Network Access preflights", func() {
			// Chromium sends this header when a public site addresses a private IP,
			// e.g. a hosted Grafana dashboard calling the blocky API on a LAN.
			res := preflight(map[string]string{"Access-Control-Request-Private-Network": "true"})

			Expect(res.Header.Get("Access-Control-Allow-Private-Network")).Should(Equal("true"))
		})
	})
})
