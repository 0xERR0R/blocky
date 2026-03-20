package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/mock"

	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// testConfigReloader is a test stub implementing ConfigReloader.
type testConfigReloader struct {
	cfg       *config.Config
	reloadErr error
}

func (r *testConfigReloader) Reload() error {
	return r.reloadErr
}

func (r *testConfigReloader) ActiveConfig() *config.Config {
	return r.cfg
}

// testResolverLookup is a test helper that implements ResolverLookup using individual mocks.
type testResolverLookup struct {
	control   BlockingControl
	querier   Querier
	refresher ListRefresher
	cache     CacheControl
}

func (t *testResolverLookup) BlockingControl() (BlockingControl, error) {
	return t.control, nil
}

func (t *testResolverLookup) ListRefresher() (ListRefresher, error) {
	return t.refresher, nil
}

func (t *testResolverLookup) CacheControl() (CacheControl, error) {
	return t.cache, nil
}

func (t *testResolverLookup) Query(
	ctx context.Context, serverHost string, clientIP net.IP, question string, qType dns.Type,
) (*model.Response, error) {
	return t.querier.Query(ctx, serverHost, clientIP, question, qType)
}

var _ = Describe("API implementation tests", func() {
	var (
		blockingControlMock *MockBlockingControl
		querierMock         *MockQuerier
		listRefreshMock     *MockListRefresher
		cacheControlMock    *MockCacheControl
		configReloaderStub  *testConfigReloader
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
		configReloaderStub = &testConfigReloader{cfg: &config.Config{}}
		sut = NewOpenAPIInterfaceImpl(&testResolverLookup{
			control:   blockingControlMock,
			querier:   querierMock,
			refresher: listRefreshMock,
			cache:     cacheControlMock,
		}, configReloaderStub)
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

	Describe("Config API", func() {
		When("GetConfig is called", func() {
			It("should return 200 with config as YAML", func() {
				resp, err := sut.GetConfig(ctx, GetConfigRequestObject{})
				Expect(err).Should(Succeed())
				var resp200 GetConfig200TextyamlResponse
				Expect(resp).Should(BeAssignableToTypeOf(resp200))
			})
		})

		Describe("redactSecrets", func() {
			It("should redact string values for sensitive keys", func() {
				data := map[interface{}]interface{}{
					"password":  "supersecret",
					"apiKey":    "key123",
					"api_key":   "key456",
					"token":     "tok789",
					"secret":    "s3cr3t",
					"safeField": "visible",
				}

				redactSecrets(data)

				Expect(data["password"]).Should(Equal("***"))
				Expect(data["apiKey"]).Should(Equal("***"))
				Expect(data["api_key"]).Should(Equal("***"))
				Expect(data["token"]).Should(Equal("***"))
				Expect(data["secret"]).Should(Equal("***"))
				Expect(data["safeField"]).Should(Equal("visible"))
			})

			It("should redact nested sensitive keys", func() {
				data := map[string]interface{}{
					"redis": map[interface{}]interface{}{
						"password": "redispass",
						"address":  "localhost:6379",
					},
				}

				redactSecrets(data)

				nested := data["redis"].(map[interface{}]interface{})
				Expect(nested["password"]).Should(Equal("***"))
				Expect(nested["address"]).Should(Equal("localhost:6379"))
			})

			It("should handle sensitive keys in slices", func() {
				data := []interface{}{
					map[string]interface{}{
						"password": "secret1",
						"name":     "test",
					},
				}

				redactSecrets(data)

				entry := data[0].(map[string]interface{})
				Expect(entry["password"]).Should(Equal("***"))
				Expect(entry["name"]).Should(Equal("test"))
			})

			It("should not redact non-string sensitive values", func() {
				data := map[interface{}]interface{}{
					"password": 12345,
				}

				redactSecrets(data)

				Expect(data["password"]).Should(Equal(12345))
			})

			It("should be case insensitive for key matching", func() {
				data := map[string]interface{}{
					"PASSWORD": "secret",
					"ApiKey":   "key",
					"TOKEN":    "tok",
				}

				redactSecrets(data)

				Expect(data["PASSWORD"]).Should(Equal("***"))
				Expect(data["ApiKey"]).Should(Equal("***"))
				Expect(data["TOKEN"]).Should(Equal("***"))
			})
		})

		When("ConfigReload is called", func() {
			It("should return 200 on success", func() {
				configReloaderStub.reloadErr = nil
				resp, err := sut.ConfigReload(ctx, ConfigReloadRequestObject{})
				Expect(err).Should(Succeed())
				var resp200 ConfigReload200Response
				Expect(resp).Should(BeAssignableToTypeOf(resp200))
			})

			It("should return 500 on failure", func() {
				configReloaderStub.reloadErr = errors.New("reload failed")
				resp, err := sut.ConfigReload(ctx, ConfigReloadRequestObject{})
				Expect(err).Should(Succeed())
				var resp500 ConfigReload500TextResponse
				Expect(resp).Should(BeAssignableToTypeOf(resp500))
				Expect(resp).Should(Equal(ConfigReload500TextResponse("reload failed")))
			})
		})
	})
})
