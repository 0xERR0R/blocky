package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/0xERR0R/blocky/api"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Blocking command", func() {
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
	Describe("Call query command", func() {
		BeforeEach(func() {
			mockFn = func(w http.ResponseWriter, _ *http.Request) {
				response, err := json.Marshal(api.ApiQueryResult{
					Reason:       "Reason",
					ResponseType: "Type",
					Response:     "Response",
					ReturnCode:   "NOERROR",
				})
				Expect(err).Should(Succeed())

				_, err = w.Write(response)
				Expect(err).Should(Succeed())
			}
		})
		When("query command is called via REST", func() {
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Add("Content-Type", "application/json")
					response, err := json.Marshal(api.ApiQueryResult{
						Reason:       "Reason",
						ResponseType: "Type",
						Response:     "Response",
						ReturnCode:   "NOERROR",
					})
					Expect(err).Should(Succeed())

					_, err = w.Write(response)
					Expect(err).Should(Succeed())
				}
			})
			It("should print result", func() {
				Expect(query(NewQueryCommand(), []string{"google.de"})).Should(Succeed())
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
				err := query(NewQueryCommand(), []string{"google.de"})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("500 Internal Server Error"))
			})
		})
		When("Type is wrong", func() {
			It("should end with error", func() {
				command := NewQueryCommand()
				command.SetArgs([]string{"--type", "X", "google.de"})
				err := command.Execute()
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("unknown query type 'X'"))
			})
		})
		When("Url is wrong", func() {
			It("should end with error", func() {
				apiPort = 0
				err := query(NewQueryCommand(), []string{"google.de"})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("connection refused"))
			})
		})
	})
})
