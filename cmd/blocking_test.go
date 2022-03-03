package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"

	"github.com/0xERR0R/blocky/api"

	. "github.com/onsi/ginkgo/v2"
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
	Describe("enable blocking", func() {
		When("Enable blocking is called via REST", func() {
			It("should enable the blocking status", func() {
				enableBlocking(newBlockingCommand(), []string{})
				Expect(loggerHook.LastEntry().Message).Should(Equal("OK"))
			})
		})
		When("Wrong url is used", func() {
			It("Should end with error", func() {
				apiPort = 0
				enableBlocking(newBlockingCommand(), []string{})
				Expect(fatal).Should(BeTrue())
				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("connection refused"))
			})
		})
		When("Server returns internal error", func() {
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			It("Should end with error", func() {
				enableBlocking(newBlockingCommand(), []string{})
				Expect(fatal).Should(BeTrue())
				Expect(loggerHook.LastEntry().Message).Should(Equal("NOK: 500 Internal Server Error"))
			})
		})
	})
	Describe("disable blocking", func() {
		When("disable blocking is called via REST", func() {
			It("should enable the blocking status", func() {
				disableBlocking(newBlockingCommand(), []string{})
				Expect(loggerHook.LastEntry().Message).Should(Equal("OK"))
			})
		})
		When("Wrong url is used", func() {
			It("Should end with error", func() {
				apiPort = 0
				disableBlocking(newBlockingCommand(), []string{})
				Expect(fatal).Should(BeTrue())
				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("connection refused"))
			})
		})
		When("Server returns internal error", func() {
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			It("Should end with error", func() {
				disableBlocking(newBlockingCommand(), []string{})
				Expect(fatal).Should(BeTrue())
				Expect(loggerHook.LastEntry().Message).Should(Equal("NOK: 500 Internal Server Error"))
			})
		})
	})
	Describe("status blocking", func() {
		When("status blocking is called via REST and blocking is enabled", func() {
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					response, _ := json.Marshal(api.BlockingStatus{
						Enabled:         true,
						AutoEnableInSec: uint(5),
					})
					_, err := w.Write(response)
					Expect(err).Should(Succeed())
				}
			})
			It("should query the blocking status", func() {
				statusBlocking(newBlockingCommand(), []string{})
				Expect(loggerHook.LastEntry().Message).Should(Equal("blocking enabled"))
			})
		})
		When("status blocking is called via REST and blocking is disabled", func() {
			var autoEnable uint
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					response, _ := json.Marshal(api.BlockingStatus{
						Enabled:         false,
						AutoEnableInSec: autoEnable,
						DisabledGroups:  []string{"abc"},
					})
					_, err := w.Write(response)
					Expect(err).Should(Succeed())
				}
			})
			It("should show the blocking status with time", func() {
				autoEnable = 5
				statusBlocking(newBlockingCommand(), []string{})
				Expect(loggerHook.LastEntry().Message).Should(Equal("blocking disabled for groups: abc, for 5 seconds"))
			})
			It("should show the blocking status", func() {
				autoEnable = 0
				statusBlocking(newBlockingCommand(), []string{})
				Expect(loggerHook.LastEntry().Message).Should(Equal("blocking disabled for groups: abc"))
			})
		})
		When("Wrong url is used", func() {
			It("Should end with error", func() {
				apiPort = 0
				statusBlocking(newBlockingCommand(), []string{})
				Expect(fatal).Should(BeTrue())
				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("connection refused"))
			})
		})
		When("Server returns internal error", func() {
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			It("Should end with error", func() {
				statusBlocking(newBlockingCommand(), []string{})
				Expect(fatal).Should(BeTrue())
				Expect(loggerHook.LastEntry().Message).Should(Equal("NOK: 500 Internal Server Error"))
			})
		})
	})
})

func testHTTPAPIServer(fn func(w http.ResponseWriter, _ *http.Request)) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(fn))
	u, _ := url.Parse(ts.URL)
	apiHost = u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	apiPort = uint16(port)

	return ts
}
