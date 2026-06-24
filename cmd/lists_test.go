package cmd

import (
	"net/http"
	"net/http/httptest"

	"github.com/0xERR0R/blocky/log"
	"github.com/spf13/cobra"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Lists command", func() {
	var (
		ts     *httptest.Server
		mockFn func(w http.ResponseWriter, _ *http.Request)
		rec    *log.Recorder
		c      *cobra.Command
		err    error
	)
	JustBeforeEach(func() {
		ts = testHTTPAPIServer(mockFn)
	})
	JustAfterEach(func() {
		ts.Close()
	})
	BeforeEach(func() {
		mockFn = func(w http.ResponseWriter, _ *http.Request) {}
		var restore func()
		rec, restore = log.CaptureGlobal()
		DeferCleanup(restore)
	})
	Describe("Call list refresh command", func() {
		When("list refresh is executed", func() {
			It("should print result", func() {
				err = refreshList(withContext(newRefreshCommand()), nil)
				Expect(err).Should(Succeed())

				Expect(rec.LastMessage()).Should(ContainSubstring("OK"))
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
