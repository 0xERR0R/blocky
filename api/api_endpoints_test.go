package api

import (
	"encoding/json"
	"net/http"
	"time"

	. "github.com/0xERR0R/blocky/helpertest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/go-chi/chi/v5"
)

type BlockingControlMock struct {
	enabled bool
}

type ListRefreshMock struct {
	refreshTriggered bool
}

func (l *ListRefreshMock) RefreshLists() {
	l.refreshTriggered = true
}

func (b *BlockingControlMock) EnableBlocking() {
	b.enabled = true
}
func (b *BlockingControlMock) DisableBlocking(_ time.Duration, disableGroups []string) error {
	b.enabled = false
	return nil
}

func (b *BlockingControlMock) BlockingStatus() BlockingStatus {
	return BlockingStatus{Enabled: b.enabled}
}

var _ = Describe("API tests", func() {

	Describe("Register router", func() {
		RegisterEndpoint(chi.NewRouter(), &BlockingControlMock{})
		RegisterEndpoint(chi.NewRouter(), &ListRefreshMock{})
	})

	Describe("Lists API", func() {

		When("List refresh is called", func() {
			r := &ListRefreshMock{}
			sut := &ListRefreshEndpoint{refresher: r}
			It("should trigger the list refresh", func() {
				httpCode, _ := DoGetRequest("/api/lists/refresh", sut.apiListRefresh)
				Expect(httpCode).Should(Equal(http.StatusOK))
				Expect(r.refreshTriggered).Should(BeTrue())
			})
		})

	})

	Describe("Control blocking status via API", func() {
		var (
			bc  *BlockingControlMock
			sut *BlockingEndpoint
		)

		BeforeEach(func() {
			bc = &BlockingControlMock{enabled: true}
			sut = &BlockingEndpoint{control: bc}
		})

		When("Disable blocking is called", func() {
			It("should disable blocking resolver", func() {
				By("Calling Rest API to deactivate", func() {

					httpCode, _ := DoGetRequest("/api/blocking/disable", sut.apiBlockingDisable)
					Expect(httpCode).Should(Equal(http.StatusOK))
					Expect(bc.enabled).Should(BeFalse())
				})
			})
		})

		When("Disable blocking is called with a wrong parameter", func() {
			It("Should return http bad request as return code", func() {
				httpCode, _ := DoGetRequest("/api/blocking/disable?duration=xyz", sut.apiBlockingDisable)

				Expect(httpCode).Should(Equal(http.StatusBadRequest))
			})
		})

		When("Disable blocking is called with a duration parameter", func() {
			It("Should disable blocking only for the passed amount of time", func() {
				By("ensure that the blocking status is active", func() {
					Expect(bc.enabled).Should(BeTrue())
				})

				By("Calling Rest API to deactivate blocking for 0.5 sec", func() {
					httpCode, _ := DoGetRequest("/api/blocking/disable?duration=500ms", sut.apiBlockingDisable)
					Expect(httpCode).Should(Equal(http.StatusOK))
				})

				By("ensure that the blocking is disabled", func() {
					// now is blocking disabled
					Expect(bc.enabled).Should(BeFalse())
				})
			})
		})

		When("Blocking status is called", func() {
			It("should return correct status", func() {
				By("enable blocking via API", func() {
					httpCode, _ := DoGetRequest("/api/blocking/enable", sut.apiBlockingEnable)
					Expect(httpCode).Should(Equal(http.StatusOK))
				})

				By("Query blocking status via API should return 'enabled'", func() {
					httpCode, body := DoGetRequest("/api/blocking/status", sut.apiBlockingStatus)
					Expect(httpCode).Should(Equal(http.StatusOK))
					var result BlockingStatus
					err := json.NewDecoder(body).Decode(&result)
					Expect(err).Should(Succeed())

					Expect(result.Enabled).Should(BeTrue())
				})

				By("disable blocking via API", func() {
					httpCode, _ := DoGetRequest("/api/blocking/disable?duration=500ms", sut.apiBlockingDisable)
					Expect(httpCode).Should(Equal(http.StatusOK))
				})

				By("Query blocking status via API again should return 'disabled'", func() {
					httpCode, body := DoGetRequest("/api/blocking/status", sut.apiBlockingStatus)
					Expect(httpCode).Should(Equal(http.StatusOK))

					var result BlockingStatus
					err := json.NewDecoder(body).Decode(&result)
					Expect(err).Should(Succeed())

					Expect(result.Enabled).Should(BeFalse())
				})
			})
		})
	})
})
