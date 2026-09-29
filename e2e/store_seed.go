package e2e

import (
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/miekg/dns"

	"github.com/0xERR0R/blocky/auth"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/configstore"
	"github.com/0xERR0R/blocky/util"
)

// The fork keeps upstream, blocking and customDNS configuration in the SQLite
// config store, and the overlay that applies it *replaces* those sections of
// the YAML rather than merging into them — deliberately, see
// docs/UPSTREAM_SYNC.md §3.4. A fixture's `blocking:` and `customDNS:` blocks
// are therefore inert on their own: the store is the only surface the running
// server reads them from, and a store with no rows means no blocking and no
// custom DNS however much YAML the fixture declares.
//
// So the bridge translates them, exactly as it already translates `upstreams:`.
// These run after config.LoadConfig has parsed the fixture, which means the
// translation works on real config.BytesSource / dns.RR values rather than
// re-parsing YAML by hand: each function here is the inverse of its
// counterpart in configstore/convert.go.
//
// What the bridge deliberately does *not* produce, because YAML cannot express
// it and the overlay reads it back as something the fixture already has:
//
//   - DomainEntry rows. An individual domain in a fixture arrives as an inline
//     text BytesSource, so it is stored as a text BlocklistSource and comes
//     back verbatim. convert.go's ListDomainEntries branch (the one that wraps
//     regex entries in slashes) is a web-UI shape, and stays e2e-unexercised.
//   - ClientGroup rows holding more than one client. clientGroupsBlock is keyed
//     per client, so one key is one group here; the UI can group several.
//   - CNAME custom-DNS entries. `mapping:` only parses IPs. rrToEntryValue
//     handles CNAME anyway so the inverse is total, not because a fixture can
//     reach it.

// defaultGroupName is the name both group namespaces reserve for their
// catch-all. For client groups, BuildBlockingConfig turns this group's Groups
// into clientGroupsBlock["default"] instead of keying them by each of its
// Clients. For upstream groups, it is the one group the store refuses to leave
// empty (see resetAndSeedGroups). Same string, unrelated tables.
const defaultGroupName = "default"

// seedBlockingConfig writes a fixture's parsed `blocking:` section into the
// store. Inverse of (*configstore.ConfigStore).BuildBlockingConfig.
//
// Schedules, listSchedules and loading are not seeded because the overlay does
// not replace them — they survive from YAML.
func seedBlockingConfig(store *configstore.ConfigStore, cfg config.Blocking) error {
	lists := []struct {
		listType string
		groups   map[string][]config.BytesSource
	}{
		{"deny", cfg.Denylists},
		{"allow", cfg.Allowlists},
	}

	for _, l := range lists {
		// Sorted so the rows land in a stable order: ListBlocklistSources
		// orders by id, and map iteration would make that order random.
		for _, group := range slices.Sorted(maps.Keys(l.groups)) {
			for _, src := range l.groups[group] {
				sourceType, err := bytesSourceTypeName(src.Type)
				if err != nil {
					return fmt.Errorf("%slist group %q: %w", l.listType, group, err)
				}

				if err := store.CreateBlocklistSource(&configstore.BlocklistSource{
					GroupName:  group,
					ListType:   l.listType,
					SourceType: sourceType,
					Source:     src.From,
					Enabled:    new(true),
				}); err != nil {
					return fmt.Errorf("seed %s source %q in group %q: %w", l.listType, src.From, group, err)
				}
			}
		}
	}

	// BuildBlockingConfig keys clientGroupsBlock by client identifier, taking
	// "default" from the group of that name and everything else from each
	// group's Clients list. One store group per YAML key reproduces that.
	// PutClientGroup derives a slug from the name and rejects an empty one or a
	// collision, so a client key of "*" — legal in clientGroupsBlock, since the
	// sanitizer strips every non-alphanumeric character — fails the seed rather
	// than the spec. Loud, but not obviously about the fixture, so: this is why.
	for _, client := range slices.Sorted(maps.Keys(cfg.ClientGroupsBlock)) {
		group := &configstore.ClientGroup{
			Name:   client,
			Groups: configstore.StringList(cfg.ClientGroupsBlock[client]),
		}

		if client != defaultGroupName {
			group.Clients = configstore.StringList{client}
		}

		if err := store.PutClientGroup(group); err != nil {
			return fmt.Errorf("seed client group %q: %w", client, err)
		}
	}

	// blockType and blockTTL are singletons with a non-empty default on both
	// sides, so there is no "unset" to leave alone: write them every time.
	if err := store.PutBlockSettings(&configstore.BlockSettings{
		BlockType: cfg.BlockType,
		// config.Duration stringifies as prose ("1 minute"), which
		// PutBlockSettings' time.ParseDuration check rejects.
		BlockTTL: cfg.BlockTTL.ToDuration().String(),
	}); err != nil {
		return fmt.Errorf("seed block settings: %w", err)
	}

	return nil
}

// seedCustomDNSConfig writes a fixture's parsed `customDNS.mapping` into the
// store. Inverse of (*configstore.ConfigStore).BuildCustomDNSConfig, which
// replaces Mapping and leaves zone, rewrite and filterUnmappedTypes to YAML.
func seedCustomDNSConfig(store *configstore.ConfigStore, cfg config.CustomDNS) error {
	// The resolver stamps CustomTTL over every mapping record's header anyway
	// (resolver/custom_dns_resolver.go), so this only keeps the stored rows
	// honest rather than deciding the answer's TTL.
	ttl := cfg.CustomTTL.SecondsU32()

	// ListCustomDNSEntries orders by (domain, record_type), so two A records for
	// one domain come back in whatever order SQLite produces — not the order the
	// fixture wrote them. Assert on a multi-IP mapping with ContainElements, not
	// on Answer[0].
	for _, domain := range slices.Sorted(maps.Keys(cfg.Mapping)) {
		for _, rr := range cfg.Mapping[domain] {
			recordType, value, err := rrToEntryValue(rr)
			if err != nil {
				return fmt.Errorf("custom DNS mapping %q: %w", domain, err)
			}

			if err := store.CreateCustomDNSEntry(&configstore.CustomDNSEntry{
				Domain:     util.ExtractDomainOnly(domain),
				RecordType: recordType,
				Value:      value,
				TTL:        ttl,
				Enabled:    new(true),
			}); err != nil {
				return fmt.Errorf("seed custom DNS entry %q: %w", domain, err)
			}
		}
	}

	return nil
}

// bytesSourceTypeName is the inverse of configstore.dbSourceToBytes. An
// unknown type is an error rather than a fallback: dbSourceToBytes defaults
// unknown source types to text, so a silent mismatch here would turn an
// unloadable list into an empty one and the spec would pass for the wrong
// reason.
func bytesSourceTypeName(t config.BytesSourceType) (string, error) {
	switch t {
	case config.BytesSourceTypeText:
		return "text", nil
	case config.BytesSourceTypeHttp:
		return "http", nil
	case config.BytesSourceTypeFile:
		return "file", nil
	default:
		return "", fmt.Errorf("unsupported list source type %q", t)
	}
}

// rrToEntryValue is the inverse of configstore.entryToRR. `mapping:` only ever
// yields A and AAAA (config.configToRR parses IPs and nothing else), but the
// store carries CNAME too, so all three round-trip.
//
// The record's header is not read: config.configToRR builds bare records with
// no header at all, and the resolver fills it in later.
func rrToEntryValue(rr dns.RR) (recordType, value string, err error) {
	switch v := rr.(type) {
	case *dns.A:
		return "A", v.A.String(), nil
	case *dns.AAAA:
		return "AAAA", v.AAAA.String(), nil
	case *dns.CNAME:
		return "CNAME", v.Target, nil
	default:
		return "", "", fmt.Errorf("unsupported record type %T", rr)
	}
}

const (
	// Credentials every seeded store carries. Each store is a throwaway file
	// mounted into one container on a private network, so fixed credentials
	// cost nothing and keep the specs from having to thread one around.
	//
	// Both roles are seeded because both are load-bearing: the admin is what
	// the API specs use, and the viewer is what proves RequireAdminForMutations
	// still rejects a read-only session.
	e2eAdminUsername  = "e2e-admin"
	e2eViewerUsername = "e2e-viewer"
	e2eAPIPassword    = "e2e-api-password"
)

// bcrypt at DefaultCost is ~60ms and both seeded accounts share one password,
// so hash it once per test process rather than twice per container.
//
//nolint:gochecknoglobals // one hash per test process, not per container
var e2eAPIPasswordHash = sync.OnceValues(func() (string, error) {
	return auth.HashPassword(e2eAPIPassword)
})

// seedAPIUsers creates the accounts the API specs log in as.
//
// server/server_endpoints.go puts every /api/* route behind auth.RequireAuth
// whenever a config store is present, and a store is now always present. With
// no users the middleware answers 401 setup_required to all of them, so a
// store without these makes the API unreachable rather than open.
func seedAPIUsers(store *configstore.ConfigStore) error {
	hash, err := e2eAPIPasswordHash()
	if err != nil {
		return fmt.Errorf("hash e2e API password: %w", err)
	}

	for _, u := range []struct{ username, role string }{
		{e2eAdminUsername, auth.RoleAdmin},
		{e2eViewerUsername, auth.RoleViewer},
	} {
		if err := store.CreateUser(&configstore.User{
			Username:     u.username,
			PasswordHash: hash,
			Role:         u.role,
		}); err != nil {
			return fmt.Errorf("seed e2e %s user: %w", u.role, err)
		}
	}

	return nil
}
