// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

//go:generate go tool oapi-codegen --config=types.cfg.yaml ../../docs/api/openapi-config.yaml
//go:generate go tool oapi-codegen --config=server.cfg.yaml ../../docs/api/openapi-config.yaml

package configapi

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
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
		Clients: derefStringList(req.Body.Clients),
		Groups:  derefStringList(req.Body.Groups),
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
		Enabled:    new(req.Body.Enabled),
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
	existing.Enabled = new(req.Body.Enabled)

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
		TTL:        uint32(req.Body.Ttl), //nolint:gosec // range-checked in validateCustomDNSEntry
		Enabled:    new(req.Body.Enabled),
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
	existing.TTL = uint32(req.Body.Ttl) //nolint:gosec // range-checked in validateCustomDNSEntry
	existing.Enabled = new(req.Body.Enabled)

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

// --- Domain Entries ---

func (h *ConfigHandler) ListDomainEntries(_ context.Context, req ListDomainEntriesRequestObject) (ListDomainEntriesResponseObject, error) {
	var entryType string
	if req.Params.EntryType != nil {
		entryType = string(*req.Params.EntryType)
	}

	entries, err := h.store.ListDomainEntries(entryType)
	if err != nil {
		return nil, err
	}

	result := make(ListDomainEntries200JSONResponse, len(entries))
	for i, e := range entries {
		result[i] = domainEntryToAPI(e)
	}

	return result, nil
}

func (h *ConfigHandler) CreateDomainEntry(_ context.Context, req CreateDomainEntryRequestObject) (CreateDomainEntryResponseObject, error) {
	if err := validateDomainEntry(req.Body); err != nil {
		return CreateDomainEntry400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	var comment string
	if req.Body.Comment != nil {
		comment = *req.Body.Comment
	}

	e := &configstore.DomainEntry{
		Domain:    req.Body.Domain,
		EntryType: string(req.Body.EntryType),
		Comment:   comment,
		Enabled:   new(req.Body.Enabled),
	}

	if err := h.store.CreateDomainEntry(e); err != nil {
		return CreateDomainEntry400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	// Auto-generate group name from ID (like blocklist sources get from URLs)
	e.GroupName = fmt.Sprintf("_d_%d", e.ID)
	if err := h.store.UpdateDomainEntry(e); err != nil {
		return CreateDomainEntry400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	// Auto-add to default client group so entries work immediately.
	// Non-fatal: if no default group exists, entry is still created.
	_ = h.store.AddGroupToClientGroup("default", e.GroupName)

	return CreateDomainEntry201JSONResponse(domainEntryToAPI(*e)), nil
}

func (h *ConfigHandler) GetDomainEntry(_ context.Context, req GetDomainEntryRequestObject) (GetDomainEntryResponseObject, error) {
	e, err := h.store.GetDomainEntry(uint(req.Id))
	if err != nil {
		if isNotFound(err) {
			return GetDomainEntry404JSONResponse{NotFoundJSONResponse{Message: "domain entry not found"}}, nil
		}

		return nil, err
	}

	return GetDomainEntry200JSONResponse(domainEntryToAPI(*e)), nil
}

func (h *ConfigHandler) UpdateDomainEntry(_ context.Context, req UpdateDomainEntryRequestObject) (UpdateDomainEntryResponseObject, error) {
	existing, err := h.store.GetDomainEntry(uint(req.Id))
	if err != nil {
		if isNotFound(err) {
			return UpdateDomainEntry404JSONResponse{NotFoundJSONResponse{Message: "domain entry not found"}}, nil
		}

		return nil, err
	}

	if err := validateDomainEntry(req.Body); err != nil {
		return UpdateDomainEntry400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	var comment string
	if req.Body.Comment != nil {
		comment = *req.Body.Comment
	}

	existing.Domain = req.Body.Domain
	existing.EntryType = string(req.Body.EntryType)
	existing.Comment = comment
	existing.Enabled = new(req.Body.Enabled)
	// GroupName is immutable — set on create, managed via client group assignments

	if err := h.store.UpdateDomainEntry(existing); err != nil {
		return UpdateDomainEntry400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	return UpdateDomainEntry200JSONResponse(domainEntryToAPI(*existing)), nil
}

func (h *ConfigHandler) DeleteDomainEntry(_ context.Context, req DeleteDomainEntryRequestObject) (DeleteDomainEntryResponseObject, error) {
	// Look up entry first to get group_name for cleanup
	entry, err := h.store.GetDomainEntry(uint(req.Id))
	if err != nil {
		if isNotFound(err) {
			return DeleteDomainEntry404JSONResponse{NotFoundJSONResponse{Message: "domain entry not found"}}, nil
		}

		return nil, err
	}

	if err := h.store.DeleteDomainEntry(uint(req.Id)); err != nil {
		return nil, err
	}

	// Remove group_name from all client groups
	if entry.GroupName != "" {
		if err := h.store.RemoveGroupFromAllClientGroups(entry.GroupName); err != nil {
			return nil, err
		}
	}

	return DeleteDomainEntry204Response{}, nil
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

// --- Upstream Groups ---

func (h *ConfigHandler) ListUpstreamGroups(_ context.Context, _ ListUpstreamGroupsRequestObject) (ListUpstreamGroupsResponseObject, error) {
	groups, err := h.store.ListUpstreamGroups()
	if err != nil {
		return nil, err
	}

	result := make(ListUpstreamGroups200JSONResponse, len(groups))
	for i, g := range groups {
		result[i] = upstreamGroupToAPI(g)
	}

	return result, nil
}

func (h *ConfigHandler) GetUpstreamGroup(_ context.Context, req GetUpstreamGroupRequestObject) (GetUpstreamGroupResponseObject, error) {
	g, err := h.store.GetUpstreamGroup(req.Name)
	if err != nil {
		if isNotFound(err) {
			return GetUpstreamGroup404JSONResponse{NotFoundJSONResponse{Message: "upstream group not found"}}, nil
		}

		return nil, err
	}

	return GetUpstreamGroup200JSONResponse(upstreamGroupToAPI(*g)), nil
}

func (h *ConfigHandler) PutUpstreamGroup(_ context.Context, req PutUpstreamGroupRequestObject) (PutUpstreamGroupResponseObject, error) {
	if strings.TrimSpace(req.Name) == "" {
		return PutUpstreamGroup400JSONResponse{BadRequestJSONResponse{Message: "upstream group name is required"}}, nil
	}

	g := &configstore.UpstreamGroup{Name: req.Name}

	if err := h.store.PutUpstreamGroup(g); err != nil {
		return PutUpstreamGroup400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	return PutUpstreamGroup200JSONResponse(upstreamGroupToAPI(*g)), nil
}

func (h *ConfigHandler) DeleteUpstreamGroup(_ context.Context, req DeleteUpstreamGroupRequestObject) (DeleteUpstreamGroupResponseObject, error) {
	if err := h.store.DeleteUpstreamGroup(req.Name); err != nil {
		if isNotFound(err) {
			return DeleteUpstreamGroup404JSONResponse{NotFoundJSONResponse{Message: "upstream group not found"}}, nil
		}

		return DeleteUpstreamGroup400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	return DeleteUpstreamGroup204Response{}, nil
}

func (h *ConfigHandler) ListUpstreamServers(_ context.Context, req ListUpstreamServersRequestObject) (ListUpstreamServersResponseObject, error) {
	servers, err := h.store.ListUpstreamServers(req.Name)
	if err != nil {
		return nil, err
	}

	result := make(ListUpstreamServers200JSONResponse, len(servers))
	for i, s := range servers {
		result[i] = upstreamServerToAPI(s)
	}

	return result, nil
}

func (h *ConfigHandler) CreateUpstreamServer(_ context.Context, req CreateUpstreamServerRequestObject) (CreateUpstreamServerResponseObject, error) {
	if err := validateUpstreamServer(req.Body); err != nil {
		return CreateUpstreamServer400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	if _, err := h.store.GetUpstreamGroup(req.Name); err != nil {
		if isNotFound(err) {
			return CreateUpstreamServer404JSONResponse{NotFoundJSONResponse{Message: "upstream group not found"}}, nil
		}

		return nil, err
	}

	pos := 0
	if req.Body.Position != nil {
		pos = *req.Body.Position
	}

	srv := &configstore.UpstreamServer{
		GroupName: req.Name,
		URL:       req.Body.Url,
		Position:  pos,
		Enabled:   new(req.Body.Enabled),
	}

	if err := h.store.CreateUpstreamServer(srv); err != nil {
		return CreateUpstreamServer400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	return CreateUpstreamServer201JSONResponse(upstreamServerToAPI(*srv)), nil
}

func (h *ConfigHandler) UpdateUpstreamServer(_ context.Context, req UpdateUpstreamServerRequestObject) (UpdateUpstreamServerResponseObject, error) {
	existing, err := h.store.GetUpstreamServer(uint(req.Id))
	if err != nil {
		if isNotFound(err) {
			return UpdateUpstreamServer404JSONResponse{NotFoundJSONResponse{Message: "upstream server not found"}}, nil
		}

		return nil, err
	}

	if existing.GroupName != req.Name {
		return UpdateUpstreamServer404JSONResponse{NotFoundJSONResponse{Message: "upstream server not in this group"}}, nil
	}

	if err := validateUpstreamServer(req.Body); err != nil {
		return UpdateUpstreamServer400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	existing.URL = req.Body.Url
	existing.Enabled = new(req.Body.Enabled)

	if req.Body.Position != nil {
		existing.Position = *req.Body.Position
	}

	if err := h.store.UpdateUpstreamServer(existing); err != nil {
		return nil, err
	}

	return UpdateUpstreamServer200JSONResponse(upstreamServerToAPI(*existing)), nil
}

func (h *ConfigHandler) DeleteUpstreamServer(_ context.Context, req DeleteUpstreamServerRequestObject) (DeleteUpstreamServerResponseObject, error) {
	existing, err := h.store.GetUpstreamServer(uint(req.Id))
	if err != nil {
		if isNotFound(err) {
			return DeleteUpstreamServer404JSONResponse{NotFoundJSONResponse{Message: "upstream server not found"}}, nil
		}

		return nil, err
	}

	if existing.GroupName != req.Name {
		return DeleteUpstreamServer404JSONResponse{NotFoundJSONResponse{Message: "upstream server not in this group"}}, nil
	}

	if err := h.store.DeleteUpstreamServer(uint(req.Id)); err != nil {
		return DeleteUpstreamServer400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	return DeleteUpstreamServer204Response{}, nil
}

// --- Upstream Settings ---

func (h *ConfigHandler) GetUpstreamSettings(_ context.Context, _ GetUpstreamSettingsRequestObject) (GetUpstreamSettingsResponseObject, error) {
	us, err := h.store.GetUpstreamSettings()
	if err != nil {
		return nil, err
	}

	return GetUpstreamSettings200JSONResponse(upstreamSettingsToAPI(*us)), nil
}

func (h *ConfigHandler) PutUpstreamSettings(_ context.Context, req PutUpstreamSettingsRequestObject) (PutUpstreamSettingsResponseObject, error) {
	if req.Body == nil {
		return PutUpstreamSettings400JSONResponse{BadRequestJSONResponse{Message: "request body is required"}}, nil
	}

	us := &configstore.UpstreamSettings{
		Strategy:     string(req.Body.Strategy),
		Timeout:      req.Body.Timeout,
		UserAgent:    req.Body.UserAgent,
		InitStrategy: string(req.Body.InitStrategy),
	}

	if err := h.store.PutUpstreamSettings(us); err != nil {
		return PutUpstreamSettings400JSONResponse{BadRequestJSONResponse{Message: err.Error()}}, nil
	}

	return PutUpstreamSettings200JSONResponse(upstreamSettingsToAPI(*us)), nil
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
		Slug:    g.Slug,
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

func domainEntryToAPI(e configstore.DomainEntry) DomainEntry {
	return DomainEntry{
		Id:        int(e.ID),
		Domain:    e.Domain,
		EntryType: DomainEntryEntryType(e.EntryType),
		Comment:   e.Comment,
		Enabled:   e.IsEnabled(),
		GroupName: e.GroupName,
	}
}

func upstreamGroupToAPI(g configstore.UpstreamGroup) UpstreamGroup {
	return UpstreamGroup{
		Id:   int(g.ID),
		Name: g.Name,
		Slug: g.Slug,
	}
}

func upstreamServerToAPI(s configstore.UpstreamServer) UpstreamServer {
	return UpstreamServer{
		Id:        int(s.ID),
		GroupName: s.GroupName,
		Url:       s.URL,
		Position:  s.Position,
		Enabled:   s.IsEnabled(),
	}
}

func upstreamSettingsToAPI(us configstore.UpstreamSettings) UpstreamSettings {
	return UpstreamSettings{
		Strategy:     UpstreamSettingsStrategy(us.Strategy),
		Timeout:      us.Timeout,
		UserAgent:    us.UserAgent,
		InitStrategy: UpstreamSettingsInitStrategy(us.InitStrategy),
	}
}

func validateUpstreamServer(input *UpstreamServerInput) error {
	if input == nil {
		return errors.New("request body is required")
	}

	if strings.TrimSpace(input.Url) == "" {
		return errors.New("url is required")
	}

	if _, err := config.ParseUpstream(input.Url); err != nil {
		return fmt.Errorf("invalid upstream %q: %w", input.Url, err)
	}

	return nil
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
		return errors.New("request body is required")
	}

	for _, c := range derefStringList(input.Clients) {
		if _, _, err := net.ParseCIDR(c); err != nil && net.ParseIP(c) == nil {
			// Not a CIDR or IP — treat as hostname (allow any non-empty string)
			if strings.TrimSpace(c) == "" {
				return errors.New("empty client entry")
			}
		}
	}

	return nil
}

func validateBlocklistSource(input *BlocklistSourceInput) error {
	if input == nil {
		return errors.New("request body is required")
	}

	if strings.TrimSpace(input.GroupName) == "" {
		return errors.New("group_name is required")
	}

	if strings.TrimSpace(input.Source) == "" {
		return errors.New("source is required")
	}

	switch input.SourceType {
	case BlocklistSourceInputSourceTypeHttp:
		if _, err := url.ParseRequestURI(input.Source); err != nil {
			return fmt.Errorf("invalid URL: %w", err)
		}
	case BlocklistSourceInputSourceTypeFile:
		if !strings.HasPrefix(input.Source, "/") {
			return errors.New("file source must be an absolute path")
		}
	case BlocklistSourceInputSourceTypeText:
		// Text sources are inline content, no validation needed
	}

	return nil
}

func validateCustomDNSEntry(input *CustomDNSEntryInput) error {
	if input == nil {
		return errors.New("request body is required")
	}

	if strings.TrimSpace(input.Domain) == "" {
		return errors.New("domain is required")
	}

	// The wire type is a plain integer but the record carries a uint32, so an
	// out-of-range TTL would silently wrap on the way into the store.
	if input.Ttl < 0 || input.Ttl > math.MaxUint32 {
		return fmt.Errorf("ttl must be between 0 and %d", uint32(math.MaxUint32))
	}

	switch input.RecordType {
	case CustomDNSEntryInputRecordTypeA:
		if ip := net.ParseIP(input.Value); ip == nil || ip.To4() == nil {
			//nolint:staticcheck // "A record" is a DNS record type, not a capitalised sentence
			return errors.New("A record value must be a valid IPv4 address")
		}
	case CustomDNSEntryInputRecordTypeAAAA:
		if ip := net.ParseIP(input.Value); ip == nil || ip.To4() != nil {
			return errors.New("AAAA record value must be a valid IPv6 address")
		}
	case CustomDNSEntryInputRecordTypeCNAME:
		if strings.TrimSpace(input.Value) == "" {
			return errors.New("CNAME value must be a valid hostname")
		}
	}

	return nil
}

// hostnameChars is the set of characters legal in a DNS name we'd try to
// match exactly. Anything outside this set (parens, backslashes, pipes,
// asterisks, etc.) implies the caller meant a regex and picked the wrong
// entry_type — matching would silently never fire.
var hostnameChars = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func validateDomainEntry(input *DomainEntryInput) error {
	if input == nil {
		return errors.New("request body is required")
	}

	if strings.TrimSpace(input.Domain) == "" {
		return errors.New("domain is required")
	}

	switch input.EntryType {
	case DomainEntryInputEntryTypeRegexDeny, DomainEntryInputEntryTypeRegexAllow:
		if _, err := regexp.Compile(input.Domain); err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
	case DomainEntryInputEntryTypeExactDeny, DomainEntryInputEntryTypeExactAllow:
		if !hostnameChars.MatchString(strings.TrimSpace(input.Domain)) {
			return errors.New("exact entries must be a plain hostname; use regex_deny/regex_allow for patterns")
		}
	}

	return nil
}

func validateBlockSettings(input *BlockSettingsInput) error {
	if input == nil {
		return errors.New("request body is required")
	}

	switch input.BlockType {
	case "ZEROIP", "NXDOMAIN":
		// valid
	default:
		if net.ParseIP(input.BlockType) == nil {
			return errors.New("block_type must be ZEROIP, NXDOMAIN, or a valid IP address")
		}
	}

	if _, err := time.ParseDuration(input.BlockTtl); err != nil {
		return fmt.Errorf("invalid block_ttl: %w", err)
	}

	return nil
}

func derefStringList(p *[]string) configstore.StringList {
	if p == nil {
		return configstore.StringList{}
	}

	return configstore.StringList(*p)
}

func isNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}
