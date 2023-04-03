package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/stretchr/testify/mock"

	. "github.com/0xERR0R/blocky/helpertest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/go-chi/chi/v5"
)

var _ = Describe("API tests", func() {
	Describe("Register router", func() {
		var r ListRefresher
		var b BlockingControl
		BeforeEach(func() {
			r = NewMockListRefresher(GinkgoT())
			b = NewMockBlockingControl(GinkgoT())
		})
		It("should register endpoints", func() {
			RegisterEndpoint(chi.NewRouter(), b)
			RegisterEndpoint(chi.NewRouter(), r)
		})
	})

	Describe("Lists API", func() {
		When("List refresh is called", func() {
			var r *MockListRefresher
			BeforeEach(func() {
				r = NewMockListRefresher(GinkgoT())
				r.EXPECT().RefreshLists()
			})

			It("should trigger the list refresh", func() {
				sut := &ListRefreshEndpoint{refresher: r}
				resp, _ := DoGetRequest("/api/lists/refresh", sut.apiListRefresh)
				Expect(resp).Should(HaveHTTPStatus(http.StatusOK))
				Expect(resp).Should(HaveHTTPHeaderWithValue("Content-type", "application/json"))
			})
		})
	})

	Describe("Control blocking status via API", func() {
		var (
			bc  *MockBlockingControl
			sut *BlockingEndpoint
		)

		BeforeEach(func() {
			bc = NewMockBlockingControl(GinkgoT())
			sut = &BlockingEndpoint{control: bc}
		})

		When("Disable blocking is called", func() {
			It("should disable blocking resolver", func() {
				By("Calling Rest API to deactivate", func() {
					bc.EXPECT().DisableBlocking(time.Duration(0), mock.Anything).Return(nil)
					resp, _ := DoGetRequest("/api/blocking/disable", sut.apiBlockingDisable)
					Expect(resp).Should(HaveHTTPStatus(http.StatusOK))
					Expect(resp).Should(HaveHTTPHeaderWithValue("Content-type", "application/json"))
				})
			})
		})

		When("Disable blocking is called with a wrong parameter", func() {
			It("Should return http bad request as return code", func() {
				resp, _ := DoGetRequest("/api/blocking/disable?duration=xyz", sut.apiBlockingDisable)
				Expect(resp).Should(HaveHTTPStatus(http.StatusBadRequest))
				Expect(resp).Should(HaveHTTPHeaderWithValue("Content-type", "application/json"))
			})
		})

		When("Disable blocking is called with a duration parameter", func() {
			It("Should disable blocking only for the passed amount of time", func() {
				By("Calling Rest API to deactivate blocking for 0.5 sec", func() {
					bc.EXPECT().DisableBlocking(time.Millisecond*500, mock.Anything).Return(nil)
					resp, _ := DoGetRequest("/api/blocking/disable?duration=500ms", sut.apiBlockingDisable)
					Expect(resp).Should(HaveHTTPStatus(http.StatusOK))
					Expect(resp).Should(HaveHTTPHeaderWithValue("Content-type", "application/json"))
				})
			})
		})

		When("Disable blocking is called with groups parameter", func() {
			It("Should disable blocking only for passed groups", func() {
				By("Calling Rest API to deactivate blocking for special groups", func() {
					bc.EXPECT().DisableBlocking(time.Millisecond*500, []string{"group1", "group2"}).Return(nil)
					resp, _ := DoGetRequest("/api/blocking/disable?duration=500ms&groups=group1,group2", sut.apiBlockingDisable)
					Expect(resp).Should(HaveHTTPStatus(http.StatusOK))
					Expect(resp).Should(HaveHTTPHeaderWithValue("Content-type", "application/json"))
				})
			})
		})

		When("Disable blocking returns error", func() {
			It("Should return error code", func() {
				bc.EXPECT().DisableBlocking(time.Duration(0), mock.Anything).Return(errors.New("boom"))
				resp, _ := DoGetRequest("/api/blocking/disable", sut.apiBlockingDisable)
				Expect(resp).Should(HaveHTTPStatus(http.StatusBadRequest))
				Expect(resp).Should(HaveHTTPHeaderWithValue("Content-type", "application/json"))
			})
		})

		When("enable blocking is called", func() {
			It("should enable blocking resolver", func() {
				By("Calling Rest API to enable", func() {
					bc.EXPECT().EnableBlocking()
					resp, _ := DoGetRequest("/api/blocking/enable", sut.apiBlockingEnable)
					Expect(resp).Should(HaveHTTPStatus(http.StatusOK))
					Expect(resp).Should(HaveHTTPHeaderWithValue("Content-type", "application/json"))
				})
			})
		})

		When("Blocking status is called", func() {
			It("should return 'enabled'", func() {
				bc.EXPECT().BlockingStatus().Return(BlockingStatus{
					Enabled: true,
				})
				resp, body := DoGetRequest("/api/blocking/status", sut.apiBlockingStatus)
				Expect(resp).Should(HaveHTTPStatus(http.StatusOK))
				Expect(resp).Should(HaveHTTPHeaderWithValue("Content-type", "application/json"))
				var result BlockingStatus
				err := json.NewDecoder(body).Decode(&result)
				Expect(err).Should(Succeed())

				Expect(result.Enabled).Should(BeTrue())
			})
			It("should return 'disabled'", func() {
				bc.EXPECT().BlockingStatus().Return(BlockingStatus{
					Enabled:         false,
					DisabledGroups:  []string{"group1"},
					AutoEnableInSec: 30,
				})
				resp, body := DoGetRequest("/api/blocking/status", sut.apiBlockingStatus)
				Expect(resp).Should(HaveHTTPStatus(http.StatusOK))
				Expect(resp).Should(HaveHTTPHeaderWithValue("Content-type", "application/json"))
				var result BlockingStatus
				err := json.NewDecoder(body).Decode(&result)
				Expect(err).Should(Succeed())

				Expect(result.Enabled).Should(BeFalse())
				Expect(result.DisabledGroups).Should(Equal([]string{"group1"}))
				Expect(result.AutoEnableInSec).Should(BeNumerically("==", 30))
			})
		})
	})
})
