package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/mock"

	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("API implementation tests", func() {
	var (
		blockingControlMock *MockBlockingControl
		querierMock         *MockQuerier
		listRefreshMock     *MockListRefresher
		cacheControlMock    *MockCacheControl
		sut                 *OpenAPIInterfaceImpl

		ctx      context.Context
		cancelFn context.CancelFunc
	)

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		blockingControlMock = NewMockBlockingControl(GinkgoT())
		querierMock = NewMockQuerier(GinkgoT())
		listRefreshMock = NewMockListRefresher(GinkgoT())
		cacheControlMock = NewMockCacheControl(GinkgoT())
		sut = NewOpenAPIInterfaceImpl(blockingControlMock, querierMock, listRefreshMock, cacheControlMock)
	})

	Describe("RegisterOpenAPIEndpoints", func() {
		It("adds routes", func() {
			rtr := chi.NewRouter()
			RegisterOpenAPIEndpoints(rtr, sut)

			Expect(rtr.Routes()).ShouldNot(BeEmpty())
		})
	})

	Describe("ctxWithHTTPRequestMiddleware", func() {
		It("adds the request to the context", func() {
			handler := func(ctx context.Context, _ http.ResponseWriter, r *http.Request, _ any) (any, error) {
				Expect(ctx.Value(httpReqCtxKey{})).Should(BeIdenticalTo(r))

				return nil, nil //nolint:nilnil
			}

			handler = ctxWithHTTPRequestMiddleware(handler, "operation-id")

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
			Expect(err).Should(Succeed())

			resp, err := handler(ctx, nil, req, nil)
			Expect(err).Should(Succeed())
			Expect(resp).Should(BeNil())
		})
	})

	Describe("Query API", func() {
		When("Query is called", func() {
			It("should return 200 on success", func() {
				queryResponse, err := util.NewMsgWithAnswer(
					"domain.", 123, A, "0.0.0.0",
				)
				Expect(err).Should(Succeed())

				querierMock.On("Query", ctx, "", net.IP(nil), "google.com.", A).Return(&model.Response{
					Res:    queryResponse,
					Reason: "reason",
				}, nil)

				resp, err := sut.Query(ctx, QueryRequestObject{
					Body: &ApiQueryRequest{
						Query: "google.com", Type: "A",
					},
				})
				Expect(err).Should(Succeed())
				var resp200 Query200JSONResponse
				Expect(resp).Should(BeAssignableToTypeOf(resp200))
				resp200 = resp.(Query200JSONResponse)
				Expect(resp200.Reason).Should(Equal("reason"))
				Expect(resp200.Response).Should(Equal("A (0.0.0.0)"))
				Expect(resp200.ResponseType).Should(Equal("RESOLVED"))
				Expect(resp200.ReturnCode).Should(Equal("NOERROR"))
			})

			It("extracts metadata from the HTTP request", func() {
				r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://blocky.localhost", nil)
				Expect(err).Should(Succeed())

				clientIP := net.IPv4allrouter
				r.RemoteAddr = net.JoinHostPort(clientIP.String(), "89685")

				ctx = context.WithValue(ctx, httpReqCtxKey{}, r)

				expectedErr := errors.New("test")
				querierMock.On("Query", ctx, "blocky.localhost", clientIP, "example.com.", A).Return(nil, expectedErr)

				_, err = sut.Query(ctx, QueryRequestObject{
					Body: &ApiQueryRequest{
						Query: "example.com", Type: "A",
					},
				})
				Expect(err).Should(MatchError(expectedErr))
			})

			It("should return 400 on wrong parameter", func() {
				resp, err := sut.Query(ctx, QueryRequestObject{
					Body: &ApiQueryRequest{
						Query: "google.com",
						Type:  "WRONGTYPE",
					},
				})
				Expect(err).Should(Succeed())
				var resp400 Query400TextResponse
				Expect(resp).Should(BeAssignableToTypeOf(resp400))
				Expect(resp).Should(Equal(Query400TextResponse("unknown query type 'WRONGTYPE'")))
			})
		})
	})

	Describe("Lists API", func() {
		When("List refresh is called", func() {
			It("should return 200 on success", func() {
				listRefreshMock.On("RefreshLists", mock.Anything).Return(nil)

				resp, err := sut.ListRefresh(ctx, ListRefreshRequestObject{})
				Expect(err).Should(Succeed())
				var resp200 ListRefresh200Response
				Expect(resp).Should(BeAssignableToTypeOf(resp200))
			})

			It("should return 500 on failure", func() {
				listRefreshMock.On("RefreshLists", mock.Anything).Return(errors.New("failed"))

				resp, err := sut.ListRefresh(ctx, ListRefreshRequestObject{})
				Expect(err).Should(Succeed())
				var resp500 ListRefresh500TextResponse
				Expect(resp).Should(BeAssignableToTypeOf(resp500))
				Expect(resp).Should(Equal(ListRefresh500TextResponse("failed")))
			})
		})
	})

	Describe("Control blocking status via API", func() {
		When("Disable blocking is called", func() {
			It("should return a success when receiving no groups", func() {
				var emptySlice []string
				blockingControlMock.On("DisableBlocking", mock.Anything, 3*time.Second, emptySlice).Return(nil)
				duration := "3s"
				grroups := ""

				resp, err := sut.DisableBlocking(ctx, DisableBlockingRequestObject{
					Params: DisableBlockingParams{
						Duration: &duration,
						Groups:   &grroups,
					},
				})
				Expect(err).Should(Succeed())
				var resp200 DisableBlocking200Response
				Expect(resp).Should(BeAssignableToTypeOf(resp200))
			})

			It("should return 200 on success", func() {
				blockingControlMock.On("DisableBlocking", mock.Anything, 3*time.Second, []string{"gr1", "gr2"}).Return(nil)
				duration := "3s"
				grroups := "gr1,gr2"

				resp, err := sut.DisableBlocking(ctx, DisableBlockingRequestObject{
					Params: DisableBlockingParams{
						Duration: &duration,
						Groups:   &grroups,
					},
				})
				Expect(err).Should(Succeed())
				var resp200 DisableBlocking200Response
				Expect(resp).Should(BeAssignableToTypeOf(resp200))
			})

			It("should return 400 on failure", func() {
				blockingControlMock.On("DisableBlocking", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed"))
				resp, err := sut.DisableBlocking(ctx, DisableBlockingRequestObject{})
				Expect(err).Should(Succeed())
				var resp400 DisableBlocking400TextResponse
				Expect(resp).Should(BeAssignableToTypeOf(resp400))
				Expect(resp).Should(Equal(DisableBlocking400TextResponse("failed")))
			})

			It("should return 400 on wrong duration parameter", func() {
				wrongDuration := "4sds"
				resp, err := sut.DisableBlocking(ctx, DisableBlockingRequestObject{
					Params: DisableBlockingParams{
						Duration: &wrongDuration,
					},
				})
				Expect(err).Should(Succeed())
				var resp400 DisableBlocking400TextResponse
				Expect(resp).Should(BeAssignableToTypeOf(resp400))
				Expect(resp).Should(Equal(DisableBlocking400TextResponse("time: unknown unit \"sds\" in duration \"4sds\"")))
			})
		})
		When("Enable blocking is called", func() {
			It("should return 200 on success", func() {
				blockingControlMock.On("EnableBlocking", mock.Anything).Return()

				resp, err := sut.EnableBlocking(ctx, EnableBlockingRequestObject{})
				Expect(err).Should(Succeed())
				var resp200 EnableBlocking200Response
				Expect(resp).Should(BeAssignableToTypeOf(resp200))
			})
		})

		When("Blocking status is called", func() {
			It("should return 200 and correct status", func() {
				blockingControlMock.On("BlockingStatus").Return(BlockingStatus{
					Enabled:         false,
					DisabledGroups:  []string{"gr1", "gr2"},
					AutoEnableInSec: 47,
				})

				resp, err := sut.BlockingStatus(ctx, BlockingStatusRequestObject{})
				Expect(err).Should(Succeed())
				var resp200 BlockingStatus200JSONResponse
				Expect(resp).Should(BeAssignableToTypeOf(resp200))
				resp200 = resp.(BlockingStatus200JSONResponse)
				Expect(resp200.Enabled).Should(BeFalse())
				Expect(resp200.DisabledGroups).Should(HaveValue(Equal([]string{"gr1", "gr2"})))
				Expect(resp200.AutoEnableInSec).Should(HaveValue(BeNumerically("==", 47)))
			})
		})
	})

	Describe("Cache API", func() {
		When("Cache flush is called", func() {
			It("should return 200 on success", func() {
				cacheControlMock.On("FlushCaches", ctx).Return()
				resp, err := sut.CacheFlush(ctx, CacheFlushRequestObject{})
				Expect(err).Should(Succeed())
				var resp200 CacheFlush200Response
				Expect(resp).Should(BeAssignableToTypeOf(resp200))
			})
		})
	})
})
