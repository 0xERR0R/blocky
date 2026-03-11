//go:generate go tool oapi-codegen --config=types.cfg.yaml ../../docs/api/openapi-config.yaml
//go:generate go tool oapi-codegen --config=server.cfg.yaml ../../docs/api/openapi-config.yaml

package configapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/configstore"
	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
)

// Reconfigurer rebuilds the resolver chain from DB state.
type Reconfigurer interface {
	Reconfigure(ctx context.Context) error
}

type ConfigHandler struct {
	store        *configstore.ConfigStore
	reconfigurer Reconfigurer
}

func NewConfigHandler(store *configstore.ConfigStore, reconfigurer Reconfigurer) *ConfigHandler {
	return &ConfigHandler{store: store, reconfigurer: reconfigurer}
}

func RegisterEndpoints(router chi.Router, h *ConfigHandler) {
	middleware := []StrictMiddlewareFunc{}
	HandlerFromMuxWithBaseURL(NewStrictHandler(h, middleware), router, "/api/config")
}

// --- Client Groups ---

func (h *ConfigHandler) ListClientGroups(_ context.Context, _ ListClientGroupsRequestObject) (ListClientGroupsResponseObject, error) {
	groups, err := h.store.ListClientGroups()
	if err != nil {
		return nil, err
	}

	result := make(ListClientGroups200JSONResponse, len(groups))
	for i, g := range groups {
		result[i] = clientGroupToAPI(g)
	}

	return result, nil
}

func (h *ConfigHandler) GetClientGroup(_ context.Context, req GetClientGroupRequestObject) (GetClientGroupResponseObject, error) {
	g, err := h.store.GetClientGroup(req.Name)
	if err != nil {
		if isNotFound(err) {
			return GetClientGroup404JSONResponse{NotFoundJSONResponse{Message: "client group not found"}}, nil
		}

		return nil, err
	}

	return GetClientGroup200JSONResponse(clientGroupToAPI(*g)), nil
}

func (h *ConfigHandler) PutClientGroup(_ context.Context, req PutClientGroupRequestObject) (PutClientGroupResponseObject, error) {
	if err := validateClientGroup(req.Body); err != nil {
		return PutClientGroup400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	g := &configstore.ClientGroup{
		Name:    req.Name,
		Clients: configstore.StringList(req.Body.Clients),
		Groups:  configstore.StringList(req.Body.Groups),
	}

	if err := h.store.PutClientGroup(g); err != nil {
		return nil, err
	}

	return PutClientGroup200JSONResponse(clientGroupToAPI(*g)), nil
}

func (h *ConfigHandler) DeleteClientGroup(_ context.Context, req DeleteClientGroupRequestObject) (DeleteClientGroupResponseObject, error) {
	if err := h.store.DeleteClientGroup(req.Name); err != nil {
		if isNotFound(err) {
			return DeleteClientGroup404JSONResponse{NotFoundJSONResponse{Message: "client group not found"}}, nil
		}

		return nil, err
	}

	return DeleteClientGroup204Response{}, nil
}

// --- Blocklist Sources ---

func (h *ConfigHandler) ListBlocklistSources(_ context.Context, req ListBlocklistSourcesRequestObject) (ListBlocklistSourcesResponseObject, error) {
	var groupName, listType string
	if req.Params.GroupName != nil {
		groupName = *req.Params.GroupName
	}

	if req.Params.ListType != nil {
		listType = string(*req.Params.ListType)
	}

	sources, err := h.store.ListBlocklistSources(groupName, listType)
	if err != nil {
		return nil, err
	}

	result := make(ListBlocklistSources200JSONResponse, len(sources))
	for i, s := range sources {
		result[i] = blocklistSourceToAPI(s)
	}

	return result, nil
}

func (h *ConfigHandler) CreateBlocklistSource(_ context.Context, req CreateBlocklistSourceRequestObject) (CreateBlocklistSourceResponseObject, error) {
	if err := validateBlocklistSource(req.Body); err != nil {
		return CreateBlocklistSource400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	src := &configstore.BlocklistSource{
		GroupName:  req.Body.GroupName,
		ListType:   string(req.Body.ListType),
		SourceType: string(req.Body.SourceType),
		Source:     req.Body.Source,
		Enabled:    configstore.BoolPtr(req.Body.Enabled),
	}

	if err := h.store.CreateBlocklistSource(src); err != nil {
		return nil, err
	}

	return CreateBlocklistSource201JSONResponse(blocklistSourceToAPI(*src)), nil
}

func (h *ConfigHandler) GetBlocklistSource(_ context.Context, req GetBlocklistSourceRequestObject) (GetBlocklistSourceResponseObject, error) {
	src, err := h.store.GetBlocklistSource(uint(req.Id))
	if err != nil {
		if isNotFound(err) {
			return GetBlocklistSource404JSONResponse{NotFoundJSONResponse{Message: "blocklist source not found"}}, nil
		}

		return nil, err
	}

	return GetBlocklistSource200JSONResponse(blocklistSourceToAPI(*src)), nil
}

func (h *ConfigHandler) UpdateBlocklistSource(_ context.Context, req UpdateBlocklistSourceRequestObject) (UpdateBlocklistSourceResponseObject, error) {
	existing, err := h.store.GetBlocklistSource(uint(req.Id))
	if err != nil {
		if isNotFound(err) {
			return UpdateBlocklistSource404JSONResponse{NotFoundJSONResponse{Message: "blocklist source not found"}}, nil
		}

		return nil, err
	}

	if err := validateBlocklistSource(req.Body); err != nil {
		return UpdateBlocklistSource400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	existing.GroupName = req.Body.GroupName
	existing.ListType = string(req.Body.ListType)
	existing.SourceType = string(req.Body.SourceType)
	existing.Source = req.Body.Source
	existing.Enabled = configstore.BoolPtr(req.Body.Enabled)

	if err := h.store.UpdateBlocklistSource(existing); err != nil {
		return nil, err
	}

	return UpdateBlocklistSource200JSONResponse(blocklistSourceToAPI(*existing)), nil
}

func (h *ConfigHandler) DeleteBlocklistSource(_ context.Context, req DeleteBlocklistSourceRequestObject) (DeleteBlocklistSourceResponseObject, error) {
	if err := h.store.DeleteBlocklistSource(uint(req.Id)); err != nil {
		if isNotFound(err) {
			return DeleteBlocklistSource404JSONResponse{NotFoundJSONResponse{Message: "blocklist source not found"}}, nil
		}

		return nil, err
	}

	return DeleteBlocklistSource204Response{}, nil
}

// --- Custom DNS ---

func (h *ConfigHandler) ListCustomDNSEntries(_ context.Context, _ ListCustomDNSEntriesRequestObject) (ListCustomDNSEntriesResponseObject, error) {
	entries, err := h.store.ListCustomDNSEntries()
	if err != nil {
		return nil, err
	}

	result := make(ListCustomDNSEntries200JSONResponse, len(entries))
	for i, e := range entries {
		result[i] = customDNSEntryToAPI(e)
	}

	return result, nil
}

func (h *ConfigHandler) CreateCustomDNSEntry(_ context.Context, req CreateCustomDNSEntryRequestObject) (CreateCustomDNSEntryResponseObject, error) {
	if err := validateCustomDNSEntry(req.Body); err != nil {
		return CreateCustomDNSEntry400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	e := &configstore.CustomDNSEntry{
		Domain:     req.Body.Domain,
		RecordType: string(req.Body.RecordType),
		Value:      req.Body.Value,
		TTL:        uint32(req.Body.Ttl),
		Enabled:    configstore.BoolPtr(req.Body.Enabled),
	}

	if err := h.store.CreateCustomDNSEntry(e); err != nil {
		return nil, err
	}

	return CreateCustomDNSEntry201JSONResponse(customDNSEntryToAPI(*e)), nil
}

func (h *ConfigHandler) GetCustomDNSEntry(_ context.Context, req GetCustomDNSEntryRequestObject) (GetCustomDNSEntryResponseObject, error) {
	e, err := h.store.GetCustomDNSEntry(uint(req.Id))
	if err != nil {
		if isNotFound(err) {
			return GetCustomDNSEntry404JSONResponse{NotFoundJSONResponse{Message: "custom DNS entry not found"}}, nil
		}

		return nil, err
	}

	return GetCustomDNSEntry200JSONResponse(customDNSEntryToAPI(*e)), nil
}

func (h *ConfigHandler) UpdateCustomDNSEntry(_ context.Context, req UpdateCustomDNSEntryRequestObject) (UpdateCustomDNSEntryResponseObject, error) {
	existing, err := h.store.GetCustomDNSEntry(uint(req.Id))
	if err != nil {
		if isNotFound(err) {
			return UpdateCustomDNSEntry404JSONResponse{NotFoundJSONResponse{Message: "custom DNS entry not found"}}, nil
		}

		return nil, err
	}

	if err := validateCustomDNSEntry(req.Body); err != nil {
		return UpdateCustomDNSEntry400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	existing.Domain = req.Body.Domain
	existing.RecordType = string(req.Body.RecordType)
	existing.Value = req.Body.Value
	existing.TTL = uint32(req.Body.Ttl)
	existing.Enabled = configstore.BoolPtr(req.Body.Enabled)

	if err := h.store.UpdateCustomDNSEntry(existing); err != nil {
		return nil, err
	}

	return UpdateCustomDNSEntry200JSONResponse(customDNSEntryToAPI(*existing)), nil
}

func (h *ConfigHandler) DeleteCustomDNSEntry(_ context.Context, req DeleteCustomDNSEntryRequestObject) (DeleteCustomDNSEntryResponseObject, error) {
	if err := h.store.DeleteCustomDNSEntry(uint(req.Id)); err != nil {
		if isNotFound(err) {
			return DeleteCustomDNSEntry404JSONResponse{NotFoundJSONResponse{Message: "custom DNS entry not found"}}, nil
		}

		return nil, err
	}

	return DeleteCustomDNSEntry204Response{}, nil
}

// --- Block Settings ---

func (h *ConfigHandler) GetBlockSettings(_ context.Context, _ GetBlockSettingsRequestObject) (GetBlockSettingsResponseObject, error) {
	bs, err := h.store.GetBlockSettings()
	if err != nil {
		return nil, err
	}

	return GetBlockSettings200JSONResponse(blockSettingsToAPI(*bs)), nil
}

func (h *ConfigHandler) PutBlockSettings(_ context.Context, req PutBlockSettingsRequestObject) (PutBlockSettingsResponseObject, error) {
	if err := validateBlockSettings(req.Body); err != nil {
		return PutBlockSettings400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	bs := &configstore.BlockSettings{
		BlockType: req.Body.BlockType,
		BlockTTL:  req.Body.BlockTtl,
	}

	if err := h.store.PutBlockSettings(bs); err != nil {
		return nil, err
	}

	return PutBlockSettings200JSONResponse(blockSettingsToAPI(*bs)), nil
}

// --- Apply ---

func (h *ConfigHandler) ApplyConfig(ctx context.Context, _ ApplyConfigRequestObject) (ApplyConfigResponseObject, error) {
	if err := h.reconfigurer.Reconfigure(ctx); err != nil {
		errStr := err.Error()

		return ApplyConfig500JSONResponse(ApplyResponse{
			Status:  Error,
			Message: "Configuration saved but not applied",
			Error:   &errStr,
		}), nil
	}

	return ApplyConfig200JSONResponse(ApplyResponse{
		Status:  Ok,
		Message: "Configuration applied successfully",
	}), nil
}

// --- Conversion helpers ---

func clientGroupToAPI(g configstore.ClientGroup) ClientGroup {
	clients := []string(g.Clients)
	if clients == nil {
		clients = []string{}
	}

	groups := []string(g.Groups)
	if groups == nil {
		groups = []string{}
	}

	return ClientGroup{
		Id:      int(g.ID),
		Name:    g.Name,
		Clients: clients,
		Groups:  groups,
	}
}

func blocklistSourceToAPI(s configstore.BlocklistSource) BlocklistSource {
	return BlocklistSource{
		Id:         int(s.ID),
		GroupName:  s.GroupName,
		ListType:   BlocklistSourceListType(s.ListType),
		SourceType: BlocklistSourceSourceType(s.SourceType),
		Source:     s.Source,
		Enabled:    s.IsEnabled(),
	}
}

func customDNSEntryToAPI(e configstore.CustomDNSEntry) CustomDNSEntry {
	return CustomDNSEntry{
		Id:         int(e.ID),
		Domain:     e.Domain,
		RecordType: CustomDNSEntryRecordType(e.RecordType),
		Value:      e.Value,
		Ttl:        int(e.TTL),
		Enabled:    e.IsEnabled(),
	}
}

func blockSettingsToAPI(bs configstore.BlockSettings) BlockSettings {
	return BlockSettings{
		BlockType: bs.BlockType,
		BlockTtl:  bs.BlockTTL,
	}
}

// --- Validation ---

func validateClientGroup(input *ClientGroupInput) error {
	if input == nil {
		return fmt.Errorf("request body is required")
	}

	for _, c := range input.Clients {
		if _, _, err := net.ParseCIDR(c); err != nil && net.ParseIP(c) == nil {
			// Not a CIDR or IP — treat as hostname (allow any non-empty string)
			if strings.TrimSpace(c) == "" {
				return fmt.Errorf("empty client entry")
			}
		}
	}

	return nil
}

func validateBlocklistSource(input *BlocklistSourceInput) error {
	if input == nil {
		return fmt.Errorf("request body is required")
	}

	if strings.TrimSpace(input.GroupName) == "" {
		return fmt.Errorf("group_name is required")
	}

	if strings.TrimSpace(input.Source) == "" {
		return fmt.Errorf("source is required")
	}

	switch input.SourceType {
	case BlocklistSourceInputSourceTypeHttp:
		if _, err := url.ParseRequestURI(input.Source); err != nil {
			return fmt.Errorf("invalid URL: %w", err)
		}
	case BlocklistSourceInputSourceTypeFile:
		if !strings.HasPrefix(input.Source, "/") {
			return fmt.Errorf("file source must be an absolute path")
		}
	case BlocklistSourceInputSourceTypeText:
		// Text sources are inline content, no validation needed
	}

	return nil
}

func validateCustomDNSEntry(input *CustomDNSEntryInput) error {
	if input == nil {
		return fmt.Errorf("request body is required")
	}

	if strings.TrimSpace(input.Domain) == "" {
		return fmt.Errorf("domain is required")
	}

	switch input.RecordType {
	case CustomDNSEntryInputRecordTypeA:
		if ip := net.ParseIP(input.Value); ip == nil || ip.To4() == nil {
			return fmt.Errorf("A record value must be a valid IPv4 address")
		}
	case CustomDNSEntryInputRecordTypeAAAA:
		if ip := net.ParseIP(input.Value); ip == nil || ip.To4() != nil {
			return fmt.Errorf("AAAA record value must be a valid IPv6 address")
		}
	case CustomDNSEntryInputRecordTypeCNAME:
		if strings.TrimSpace(input.Value) == "" {
			return fmt.Errorf("CNAME value must be a valid hostname")
		}
	}

	return nil
}

func validateBlockSettings(input *BlockSettingsInput) error {
	if input == nil {
		return fmt.Errorf("request body is required")
	}

	switch input.BlockType {
	case "ZEROIP", "NXDOMAIN":
		// valid
	default:
		if net.ParseIP(input.BlockType) == nil {
			return fmt.Errorf("block_type must be ZEROIP, NXDOMAIN, or a valid IP address")
		}
	}

	if _, err := time.ParseDuration(input.BlockTtl); err != nil {
		return fmt.Errorf("invalid block_ttl: %w", err)
	}

	return nil
}

func isNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}
