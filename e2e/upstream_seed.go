package e2e

import (
	"fmt"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/0xERR0R/blocky/configstore"
)

// upstreamSeedCfg holds the parsed upstream configuration from a test YAML
// fixture, used to pre-seed a SQLite DB before starting a blocky container.
type upstreamSeedCfg struct {
	groups       map[string][]string // group name → server URLs (preserves test order)
	groupOrder   []string
	strategy     string
	timeout      string
	userAgent    string
	initStrategy string
}

// extractUpstreamYAML walks lines looking for a top-level `upstreams:` block
// and returns the parsed contents plus the lines with that block removed.
// The parser is intentionally simple: it relies on the fixed 2-space indent
// pattern used throughout the e2e test fixtures.
func extractUpstreamYAML(lines []string) (upstreamSeedCfg, []string) {
	seed := upstreamSeedCfg{
		groups: make(map[string][]string),
	}

	out := make([]string, 0, len(lines))
	inUpstreams := false
	inGroups := false
	currentGroup := ""

	for _, raw := range lines {
		line := raw

		if !inUpstreams {
			if strings.HasPrefix(line, "upstreams:") {
				inUpstreams = true

				continue
			}

			out = append(out, line)

			continue
		}

		// Exiting the upstreams: block — a line that starts at column 0 (no
		// leading space) that is not an empty line means we've left the block.
		if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inUpstreams = false
			inGroups = false
			currentGroup = ""
			out = append(out, line)

			continue
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Inside upstreams:, detect top-level sub-keys vs group content.
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			// 2-space indent → direct upstream fields
			inGroups = false
			currentGroup = ""

			switch {
			case trimmed == "groups:":
				inGroups = true
			case strings.HasPrefix(trimmed, "strategy:"):
				seed.strategy = yamlValue(trimmed)
			case strings.HasPrefix(trimmed, "timeout:"):
				seed.timeout = yamlValue(trimmed)
			case strings.HasPrefix(trimmed, "userAgent:"):
				seed.userAgent = yamlValue(trimmed)
			case trimmed == "init:":
				// init.strategy on the next line(s)
			}

			continue
		}

		// 4-space indent — inside groups: it's a group name;
		// inside init: it's init.strategy
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") {
			if inGroups {
				name := strings.TrimSuffix(trimmed, ":")
				currentGroup = name

				if _, ok := seed.groups[name]; !ok {
					seed.groups[name] = nil
					seed.groupOrder = append(seed.groupOrder, name)
				}

				continue
			}

			if strings.HasPrefix(trimmed, "strategy:") {
				seed.initStrategy = yamlValue(trimmed)
			}

			continue
		}

		// 6-space indent — list item under a group
		if strings.HasPrefix(line, "      - ") {
			if currentGroup == "" {
				continue
			}

			url := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			// Strip trailing inline comments for robustness
			if idx := strings.Index(url, " //"); idx >= 0 {
				url = strings.TrimSpace(url[:idx])
			}
			if idx := strings.Index(url, " #"); idx >= 0 {
				url = strings.TrimSpace(url[:idx])
			}

			seed.groups[currentGroup] = append(seed.groups[currentGroup], url)
		}
	}

	return seed, out
}

// yamlValue strips "key:" from a "key: value" fragment (after trimming).
func yamlValue(trimmed string) string {
	_, after, ok := strings.Cut(trimmed, ":")
	if !ok {
		return ""
	}

	v := strings.TrimSpace(after)
	v = strings.Trim(v, "\"'")

	return v
}

// ensureDatabasePath appends `databasePath: <p>` to lines if not already set.
func ensureDatabasePath(lines []string, dbPath string) []string {
	for _, l := range lines {
		if strings.HasPrefix(l, "databasePath:") {
			return lines
		}
	}

	return append(lines, "databasePath: "+dbPath)
}

// seedUpstreamDB creates a temporary SQLite DB file and pre-populates it with
// the given upstream seed. Returns the host path of the DB file.
func seedUpstreamDB(seed upstreamSeedCfg) (string, error) {
	f, err := os.CreateTemp("", "blocky_e2e_db-*.sqlite")
	if err != nil {
		return "", fmt.Errorf("create temp db: %w", err)
	}

	path := f.Name()
	f.Close()
	// Delete so configstore.Open creates a fresh DB
	_ = os.Remove(path)

	DeferCleanup(func() error {
		return os.Remove(path)
	})

	store, err := configstore.Open(path)
	if err != nil {
		return "", err
	}
	defer store.Close()

	// Replace the seeded default group's servers with anything the test
	// specified. If the test specified no groups at all, leave the built-in
	// seed (1.1.1.1 / 1.0.0.1) in place.
	if len(seed.groupOrder) > 0 {
		// Rebuild default + any extra test groups from scratch.
		if err := resetAndSeedGroups(store, seed); err != nil {
			return "", err
		}
	}

	// Apply upstream settings if any test overrode them
	if seed.strategy != "" || seed.timeout != "" || seed.userAgent != "" || seed.initStrategy != "" {
		us, err := store.GetUpstreamSettings()
		if err != nil {
			return "", err
		}

		if seed.strategy != "" {
			us.Strategy = seed.strategy
		}

		if seed.timeout != "" {
			us.Timeout = seed.timeout
		}

		if seed.userAgent != "" {
			us.UserAgent = seed.userAgent
		}

		if seed.initStrategy != "" {
			us.InitStrategy = seed.initStrategy
		}

		if err := store.PutUpstreamSettings(us); err != nil {
			return "", err
		}
	}

	return path, nil
}

// resetAndSeedGroups deletes all existing upstream servers/groups (except the
// default group, which we keep but clear) and repopulates them from seed.
func resetAndSeedGroups(store *configstore.ConfigStore, seed upstreamSeedCfg) error {
	existingGroups, err := store.ListUpstreamGroups()
	if err != nil {
		return err
	}

	// Delete non-default groups so we start fresh
	for _, g := range existingGroups {
		if g.Name == "default" {
			continue
		}

		if err := store.DeleteUpstreamGroup(g.Name); err != nil {
			return err
		}
	}

	// Clear default group servers by re-creating them: first add a placeholder,
	// then delete the real ones, then add the seeded ones, then remove the
	// placeholder. The configstore refuses to delete the last server in the
	// default group, so we keep at least one live at all times.
	defaultServers, err := store.ListUpstreamServers("default")
	if err != nil {
		return err
	}

	placeholder := &configstore.UpstreamServer{
		GroupName: "default",
		URL:       "127.0.0.1",
		Position:  9999,
		Enabled:   new(true),
	}
	if err := store.CreateUpstreamServer(placeholder); err != nil {
		return err
	}

	for _, srv := range defaultServers {
		if err := store.DeleteUpstreamServer(srv.ID); err != nil {
			return err
		}
	}

	// Now seed groups from the test fixture
	for _, name := range seed.groupOrder {
		if name != "default" {
			if err := store.PutUpstreamGroup(&configstore.UpstreamGroup{Name: name}); err != nil {
				return err
			}
		}

		for i, url := range seed.groups[name] {
			srv := &configstore.UpstreamServer{
				GroupName: name,
				URL:       url,
				Position:  i,
				Enabled:   new(true),
			}
			if err := store.CreateUpstreamServer(srv); err != nil {
				return fmt.Errorf("seed server %q in group %q: %w", url, name, err)
			}
		}
	}

	// Finally, remove the placeholder from default
	if err := store.DeleteUpstreamServer(placeholder.ID); err != nil {
		return err
	}

	Expect(seed.groups).NotTo(BeNil())

	return nil
}
