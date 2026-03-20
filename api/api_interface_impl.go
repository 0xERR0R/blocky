//go:generate go tool oapi-codegen --config=types.cfg.yaml ../docs/api/openapi.yaml
//go:generate go tool oapi-codegen --config=server.cfg.yaml ../docs/api/openapi.yaml
//go:generate go tool oapi-codegen --config=client.cfg.yaml ../docs/api/openapi.yaml

package api

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

type httpReqCtxKey struct{}

// BlockingStatus represents the current blocking status
type BlockingStatus struct {
	// True if blocking is enabled
	Enabled bool
	// Disabled group names
	DisabledGroups []string
	// If blocking is temporarily disabled: amount of seconds until blocking will be enabled
	AutoEnableInSec int
}

// BlockingControl interface to control the blocking status
type BlockingControl interface {
	EnableBlocking(ctx context.Context)
	DisableBlocking(ctx context.Context, duration time.Duration, disableGroups []string) error
	BlockingStatus() BlockingStatus
}

// ListRefresher interface to control the list refresh
type ListRefresher interface {
	RefreshLists(ctx context.Context) error
}

type Querier interface {
	Query(
		ctx context.Context, serverHost string, clientIP net.IP, question string, qType dns.Type,
	) (*model.Response, error)
}

type CacheControl interface {
	FlushCaches(ctx context.Context)
}

// ResolverLookup provides dynamic lookup of resolver interfaces from the current chain.
type ResolverLookup interface {
	BlockingControl() (BlockingControl, error)
	ListRefresher() (ListRefresher, error)
	CacheControl() (CacheControl, error)
	Querier
}

// ConfigReloader provides config reload and active config retrieval.
type ConfigReloader interface {
	Reload() error
	ActiveConfig() *config.Config
}

func RegisterOpenAPIEndpoints(router chi.Router, impl StrictServerInterface) {
	middleware := []StrictMiddlewareFunc{ctxWithHTTPRequestMiddleware}

	HandlerFromMuxWithBaseURL(NewStrictHandler(impl, middleware), router, "/api")
}

func ctxWithHTTPRequestMiddleware(handler StrictHandlerFunc, operationID string) StrictHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (response any, err error) {
		ctx = context.WithValue(ctx, httpReqCtxKey{}, r)

		return handler(ctx, w, r, request)
	}
}

type OpenAPIInterfaceImpl struct {
	lookup   ResolverLookup
	reloader ConfigReloader
}

func NewOpenAPIInterfaceImpl(lookup ResolverLookup, reloader ConfigReloader) *OpenAPIInterfaceImpl {
	return &OpenAPIInterfaceImpl{lookup: lookup, reloader: reloader}
}

func (i *OpenAPIInterfaceImpl) DisableBlocking(ctx context.Context,
	request DisableBlockingRequestObject,
) (DisableBlockingResponseObject, error) {
	control, err := i.lookup.BlockingControl()
	if err != nil {
		return DisableBlocking400TextResponse("blocking not available"), nil //nolint:nilerr
	}

	var (
		duration time.Duration
		groups   []string
	)

	if request.Params.Duration != nil {
		duration, err = time.ParseDuration(*request.Params.Duration)
		if err != nil {
			return DisableBlocking400TextResponse(log.EscapeInput(err.Error())), nil
		}
	}

	if request.Params.Groups != nil && len(*request.Params.Groups) > 0 {
		groups = strings.Split(*request.Params.Groups, ",")
	}

	err = control.DisableBlocking(ctx, duration, groups)
	if err != nil {
		return DisableBlocking400TextResponse(log.EscapeInput(err.Error())), nil
	}

	return DisableBlocking200Response{}, nil
}

func (i *OpenAPIInterfaceImpl) EnableBlocking(ctx context.Context, _ EnableBlockingRequestObject,
) (EnableBlockingResponseObject, error) {
	control, err := i.lookup.BlockingControl()
	if err != nil {
		return EnableBlocking200Response{}, nil //nolint:nilerr
	}

	control.EnableBlocking(ctx)

	return EnableBlocking200Response{}, nil
}

func (i *OpenAPIInterfaceImpl) BlockingStatus(_ context.Context, _ BlockingStatusRequestObject,
) (BlockingStatusResponseObject, error) {
	control, err := i.lookup.BlockingControl()
	if err != nil {
		return BlockingStatus200JSONResponse(ApiBlockingStatus{Enabled: false}), nil //nolint:nilerr
	}

	blStatus := control.BlockingStatus()

	result := ApiBlockingStatus{
		Enabled: blStatus.Enabled,
	}

	if blStatus.AutoEnableInSec > 0 {
		result.AutoEnableInSec = &blStatus.AutoEnableInSec
	}

	if len(blStatus.DisabledGroups) > 0 {
		result.DisabledGroups = &blStatus.DisabledGroups
	}

	return BlockingStatus200JSONResponse(result), nil
}

func (i *OpenAPIInterfaceImpl) ListRefresh(ctx context.Context,
	_ ListRefreshRequestObject,
) (ListRefreshResponseObject, error) {
	refresher, err := i.lookup.ListRefresher()
	if err != nil {
		return ListRefresh500TextResponse("list refresh not available"), nil //nolint:nilerr
	}

	err = refresher.RefreshLists(ctx)
	if err != nil {
		return ListRefresh500TextResponse(log.EscapeInput(err.Error())), nil
	}

	return ListRefresh200Response{}, nil
}

func (i *OpenAPIInterfaceImpl) Query(ctx context.Context, request QueryRequestObject) (QueryResponseObject, error) {
	qType := dns.Type(dns.StringToType[request.Body.Type])
	if qType == dns.Type(dns.TypeNone) {
		return Query400TextResponse(fmt.Sprintf("unknown query type '%s'", request.Body.Type)), nil
	}

	var (
		serverHost string
		clientIP   net.IP
	)

	httpReq, ok := ctx.Value(httpReqCtxKey{}).(*http.Request)
	if ok {
		serverHost = httpReq.Host
		clientIP = util.HTTPClientIP(httpReq)
	}

	resp, err := i.lookup.Query(ctx, serverHost, clientIP, dns.Fqdn(request.Body.Query), qType)
	if err != nil {
		return nil, fmt.Errorf("query failed for '%s' (type %s): %w", request.Body.Query, request.Body.Type, err)
	}

	return Query200JSONResponse(ApiQueryResult{
		Reason:       resp.Reason,
		ResponseType: resp.RType.String(),
		Response:     util.AnswerToString(resp.Res.Answer),
		ReturnCode:   dns.RcodeToString[resp.Res.Rcode],
	}), nil
}

func (i *OpenAPIInterfaceImpl) CacheFlush(ctx context.Context,
	_ CacheFlushRequestObject,
) (CacheFlushResponseObject, error) {
	cacheControl, err := i.lookup.CacheControl()
	if err != nil {
		return CacheFlush200Response{}, nil //nolint:nilerr
	}

	cacheControl.FlushCaches(ctx)

	return CacheFlush200Response{}, nil
}

func (i *OpenAPIInterfaceImpl) GetConfig(_ context.Context,
	_ GetConfigRequestObject,
) (GetConfigResponseObject, error) {
	cfg := i.reloader.ActiveConfig()

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	// Redact sensitive fields before returning
	var raw interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config for redaction: %w", err)
	}

	redactSecrets(raw)

	data, err = yaml.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal redacted config: %w", err)
	}

	return GetConfig200TextyamlResponse{
		Body:          bytes.NewReader(data),
		ContentLength: int64(len(data)),
	}, nil
}

// redactSecrets walks a YAML-decoded structure and replaces values for keys
// that look like they contain sensitive data with "***".
func redactSecrets(v interface{}) {
	switch val := v.(type) {
	case map[interface{}]interface{}:
		for k, child := range val {
			if s, ok := k.(string); ok && isSensitiveKey(s) {
				if _, isStr := child.(string); isStr {
					val[k] = "***"

					continue
				}
			}

			redactSecrets(child)
		}
	case map[string]interface{}:
		for k, child := range val {
			if isSensitiveKey(k) {
				if _, isStr := child.(string); isStr {
					val[k] = "***"

					continue
				}
			}

			redactSecrets(child)
		}
	case []interface{}:
		for _, child := range val {
			redactSecrets(child)
		}
	}
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)

	for _, s := range []string{"password", "passwd", "secret", "token", "apikey", "api_key"} {
		if strings.Contains(lower, s) {
			return true
		}
	}

	return false
}

func (i *OpenAPIInterfaceImpl) ConfigReload(_ context.Context,
	_ ConfigReloadRequestObject,
) (ConfigReloadResponseObject, error) {
	if err := i.reloader.Reload(); err != nil {
		return ConfigReload500TextResponse(log.EscapeInput(err.Error())), nil
	}

	return ConfigReload200Response{}, nil
}
