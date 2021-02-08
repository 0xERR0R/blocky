package cmd

import (
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Lists command", func() {
	var (
		ts     *httptest.Server
		mockFn func(w http.ResponseWriter, _ *http.Request)
	)
	JustBeforeEach(func() {
		ts = testHTTPAPIServer(mockFn)
	})
	JustAfterEach(func() {
		ts.Close()
	})
	BeforeEach(func() {
		mockFn = func(w http.ResponseWriter, _ *http.Request) {}
	})
	Describe("Call list refresh command", func() {
		When("list refresh is executed", func() {
			It("should print result", func() {
				c := NewListsCommand()
				c.SetArgs([]string{"refresh"})
				err := c.Execute()
				Expect(err).Should(Succeed())

				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("OK"))
			})
		})
		When("Server returns 500", func() {
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			It("should end with error", func() {
				_ = newRefreshCommand().Execute()
				Expect(fatal).Should(BeTrue())
				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("NOK: 500 Internal Server Error"))
			})
		})
		When("Url is wrong", func() {
			It("should end with error", func() {
				apiPort = 0
				_ = newRefreshCommand().Execute()
				Expect(fatal).Should(BeTrue())
				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("connection refused"))
			})
		})
	})
})
