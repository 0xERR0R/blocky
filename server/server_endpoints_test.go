package server

import (
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/0xERR0R/blocky/config"
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HTTP router", func() {
	var cfg config.Config

	BeforeEach(func() {
		Expect(defaults.Set(&cfg)).Should(Succeed())
	})

	get := func(path string) *httptest.ResponseRecorder {
		router := createHTTPRouter(&cfg, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		return rec
	}

	rootBody := func() string {
		body, err := io.ReadAll(get("/").Result().Body)
		Expect(err).Should(Succeed())

		return string(body)
	}

	When("pprof is enabled (default)", func() {
		It("serves the pprof endpoints and links them on the root page", func() {
			Expect(cfg.Pprof.Enable).Should(BeTrue())
			Expect(get("/debug/pprof/cmdline").Code).Should(Equal(http.StatusOK))
			Expect(rootBody()).Should(ContainSubstring(`href="/debug/"`))
		})
	})

	When("pprof is disabled", func() {
		BeforeEach(func() {
			cfg.Pprof.Enable = false
		})

		It("does not serve the pprof endpoints nor link them on the root page", func() {
			Expect(get("/debug/pprof/cmdline").Code).Should(Equal(http.StatusNotFound))
			Expect(get("/debug/pprof/").Code).Should(Equal(http.StatusNotFound))
			Expect(rootBody()).ShouldNot(ContainSubstring(`/debug/`))
		})
	})
})
