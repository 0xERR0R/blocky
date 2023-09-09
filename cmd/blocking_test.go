package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"

	"github.com/sirupsen/logrus/hooks/test"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/log"

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
	Describe("enable blocking", func() {
		When("Enable blocking is called via REST", func() {
			It("should enable the blocking status", func() {
				Expect(disableBlocking(newBlockingCommand(), []string{})).Should(Succeed())
				Expect(loggerHook.LastEntry().Message).Should(Equal("OK"))
			})
		})
		When("Wrong url is used", func() {
			It("Should end with error", func() {
				apiPort = 0
				err := enableBlocking(newBlockingCommand(), []string{})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("connection refused"))
			})
		})
		When("Server returns internal error", func() {
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			It("Should end with error", func() {
				err := enableBlocking(newBlockingCommand(), []string{})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("500 Internal Server Error"))
			})
		})
	})
	Describe("disable blocking", func() {
		When("disable blocking is called via REST", func() {
			It("should enable the blocking status", func() {
				Expect(disableBlocking(newBlockingCommand(), []string{})).Should(Succeed())
				Expect(loggerHook.LastEntry().Message).Should(Equal("OK"))
			})
		})
		When("Wrong url is used", func() {
			It("Should end with error", func() {
				apiPort = 0
				err := disableBlocking(newBlockingCommand(), []string{})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("connection refused"))
			})
		})
		When("Server returns internal error", func() {
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			It("Should end with error", func() {
				err := disableBlocking(newBlockingCommand(), []string{})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("500 Internal Server Error"))
			})
		})
	})
	Describe("status blocking", func() {
		When("status blocking is called via REST and blocking is enabled", func() {
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Add("Content-Type", "application/json")
					i := 5
					response, err := json.Marshal(api.ApiBlockingStatus{
						Enabled:         true,
						AutoEnableInSec: &i,
					})
					Expect(err).Should(Succeed())

					_, err = w.Write(response)
					Expect(err).Should(Succeed())
				}
			})
			It("should query the blocking status", func() {
				Expect(statusBlocking(newBlockingCommand(), []string{})).Should(Succeed())
				Expect(loggerHook.LastEntry().Message).Should(Equal("blocking enabled"))
			})
		})
		When("status blocking is called via REST and blocking is disabled", func() {
			var autoEnable int
			diabledGroups := []string{"abc"}
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Add("Content-Type", "application/json")
					response, err := json.Marshal(api.ApiBlockingStatus{
						Enabled:         false,
						AutoEnableInSec: &autoEnable,
						DisabledGroups:  &diabledGroups,
					})
					Expect(err).Should(Succeed())

					_, err = w.Write(response)
					Expect(err).Should(Succeed())
				}
			})
			It("should show the blocking status with time", func() {
				autoEnable = 5
				Expect(statusBlocking(newBlockingCommand(), []string{})).Should(Succeed())
				Expect(loggerHook.LastEntry().Message).Should(Equal("blocking disabled for groups: 'abc', for 5 seconds"))
			})
			It("should show the blocking status", func() {
				autoEnable = 0
				Expect(statusBlocking(newBlockingCommand(), []string{})).Should(Succeed())
				Expect(loggerHook.LastEntry().Message).Should(Equal("blocking disabled for groups: abc"))
			})
		})
		When("Wrong url is used", func() {
			It("Should end with error", func() {
				apiPort = 0
				err := statusBlocking(newBlockingCommand(), []string{})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("connection refused"))
			})
		})
		When("Server returns internal error", func() {
			BeforeEach(func() {
				mockFn = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			It("Should end with error", func() {
				err := statusBlocking(newBlockingCommand(), []string{})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("500 Internal Server Error"))
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
