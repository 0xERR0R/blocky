package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/0xERR0R/blocky/api"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Blocking command", func() {
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
	Describe("Call query command", func() {
		BeforeEach(func() {
			mockFn = func(w http.ResponseWriter, _ *http.Request) {
				response, _ := json.Marshal(api.QueryResult{
					Reason:       "Reason",
					ResponseType: "Type",
					Response:     "Response",
					ReturnCode:   "NOERROR",
				})
				_, err := w.Write(response)
				Expect(err).Should(Succeed())
			}
		})
		When("query command is called via REST", func() {
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					response, _ := json.Marshal(api.QueryResult{
						Reason:       "Reason",
						ResponseType: "Type",
						Response:     "Response",
						ReturnCode:   "NOERROR",
					})
					_, err := w.Write(response)
					Expect(err).Should(Succeed())
				}
			})
			It("should print result", func() {
				query(NewQueryCommand(), []string{"google.de"})

				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("NOERROR"))
			})
		})
		When("Server returns 500", func() {
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			It("should end with error", func() {
				query(NewQueryCommand(), []string{"google.de"})
				Expect(fatal).Should(BeTrue())
				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("NOK: 500 Internal Server Error"))
			})
		})
		When("Type is wrong", func() {
			It("should end with error", func() {

				command := NewQueryCommand()
				command.SetArgs([]string{"--type", "X", "google.de"})
				_ = command.Execute()
				Expect(fatal).Should(BeTrue())
				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("unknown query type 'X'"))
			})
		})
		When("Url is wrong", func() {
			It("should end with error", func() {
				apiPort = 0
				query(NewQueryCommand(), []string{"google.de"})
				Expect(fatal).Should(BeTrue())
				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("connection refused"))
			})
		})
	})
})
