package cmd

import (
	"net/http"
	"net/http/httptest"

	"github.com/sirupsen/logrus/hooks/test"

	"github.com/0xERR0R/blocky/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cache command", func() {
	var (
		ts         *httptest.Server
		mockFn     func(w http.ResponseWriter, _ *http.Request)
		loggerHook *test.Hook
	)
	JustBeforeEach(func() {
		ts = testHTTPAPIServer(mockFn)
	})
	JustAfterEach(func() {
		ts.Close()
	})
	BeforeEach(func() {
		mockFn = func(w http.ResponseWriter, _ *http.Request) {}
		loggerHook = test.NewGlobal()
		log.Log().AddHook(loggerHook)
	})
	AfterEach(func() {
		loggerHook.Reset()
	})
	Describe("flush cache", func() {
		When("flush cache is called via REST", func() {
			It("should flush caches", func() {
				Expect(flushCache(newCacheCommand(), []string{})).Should(Succeed())
				Expect(loggerHook.LastEntry().Message).Should(Equal("OK"))
			})
		})
		When("Wrong url is used", func() {
			It("Should end with error", func() {
				apiPort = 0
				err := flushCache(newCacheCommand(), []string{})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("connection refused"))
			})
		})
	})
})
