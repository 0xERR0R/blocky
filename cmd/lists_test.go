package cmd

import (
	"net/http"
	"net/http/httptest"

	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/cobra"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Lists command", func() {
	var (
		ts         *httptest.Server
		mockFn     func(w http.ResponseWriter, _ *http.Request)
		loggerHook *test.Hook
		c          *cobra.Command
		err        error
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
	Describe("Call list refresh command", func() {
		When("list refresh is executed", func() {
			BeforeEach(func() {
				c = NewListsCommand()
				c.SetArgs([]string{"refresh"})
			})
			It("should print result", func() {
				err = c.Execute()
				Expect(err).Should(Succeed())

				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("OK"))
			})
		})
		When("Server returns 500", func() {
			BeforeEach(func() {
				c = newRefreshCommand()
				c.SetArgs(make([]string, 0))
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			It("should end with error", func() {
				err = c.Execute()
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("500 Internal Server Error"))
			})
		})
		When("Url is wrong", func() {
			BeforeEach(func() {
				c = newRefreshCommand()
				c.SetArgs(make([]string, 0))
			})
			It("should end with error", func() {
				apiPort = 0
				err = c.Execute()
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("connection refused"))
			})
		})
	})
})
