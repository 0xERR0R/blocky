package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/configstore"
	"github.com/0xERR0R/blocky/util"
)

// Plain Go tests, like upstream_seed_test.go: they run in the fast CI job, no
// container runtime needed.
//
// What they pin is the round trip. The seed functions are the inverse of
// configstore/convert.go, and "inverse" is the whole claim: a fixture declares
// `blocking:` / `customDNS:` in YAML, the bridge writes it to the store, and
// the overlay reads it back over the very config the fixture declared. If the
// two directions disagree the container still comes up healthy — it just
// resolves differently from what the fixture asked for, which is the failure
// mode that kept 39 specs red without anyone being able to see why.

// seedTestStore builds a fixture's config, seeds a throwaway store from it and
// returns both, so a test can compare what went in with what comes back out.
func seedTestStore(t *testing.T, fixture string) (*config.Config, *configstore.ConfigStore) {
	t.Helper()

	dir := t.TempDir()

	_, stripped := extractUpstreamYAML(splitYAMLLines([]string{dedent(fixture)}))

	confPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(confPath, []byte(strings.Join(stripped, "\n")), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cfg, err := config.LoadConfig(confPath, true)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}

	store, err := configstore.Open(filepath.Join(dir, "config.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	t.Cleanup(func() { _ = store.Close() })

	if err := seedBlockingConfig(store, cfg.Blocking); err != nil {
		t.Fatalf("seed blocking: %v", err)
	}

	if err := seedCustomDNSConfig(store, cfg.CustomDNS); err != nil {
		t.Fatalf("seed custom DNS: %v", err)
	}

	return cfg, store
}

// flattenLists renders a denylist/allowlist map as comparable strings.
func flattenLists(lists map[string][]config.BytesSource) map[string][]string {
	out := make(map[string][]string, len(lists))

	for group, sources := range lists {
		for _, src := range sources {
			out[group] = append(out[group], fmt.Sprintf("%s:%s", src.Type, src.From))
		}
	}

	return out
}

// flattenMapping renders a custom DNS mapping as comparable strings, keyed the
// way the resolver keys it so that "printer.lan" and "printer.lan." compare
// equal.
func flattenMapping(mapping config.CustomDNSMapping) map[string][]string {
	out := make(map[string][]string, len(mapping))

	for domain, entries := range mapping {
		key := util.ExtractDomainOnly(domain)

		for _, rr := range entries {
			recordType, value, err := rrToEntryValue(rr)
			if err != nil {
				value = err.Error()
			}

			out[key] = append(out[key], recordType+" "+value)
		}

		slices.Sort(out[key])
	}

	return out
}

func assertSameLists(t *testing.T, what string, want, got map[string][]string) {
	t.Helper()

	if len(want) != len(got) {
		t.Fatalf("%s: want %d groups %v, got %d %v", what, len(want), want, len(got), got)
	}

	for group, wantSources := range want {
		if gotSources, ok := got[group]; !ok || !slices.Equal(wantSources, gotSources) {
			t.Errorf("%s group %q: want %v, got %v", what, group, wantSources, got[group])
		}
	}
}

func TestSeedBlockingRoundTripsThroughTheOverlay(t *testing.T) {
	fixture := `
		upstreams:
		  groups:
		    default:
		      - moka
		blocking:
		  denylists:
		    ads:
		      - http://httpserver-ads:8080/ads-list.txt
		      - http://httpserver-ads:8080/more.txt
		    malware:
		      - http://httpserver-malware:8080/malware-list.txt
		  allowlists:
		    exceptions:
		      - http://httpserver:8080/allow.txt
		      - example.com
		  clientGroupsBlock:
		    default:
		      - ads
		      - malware
		    192.168.178.55:
		      - ads
		  blockType: nxDomain
		  blockTTL: 1m
		`

	cfg, store := seedTestStore(t, fixture)

	got, err := store.BuildBlockingConfig(config.Blocking{})
	if err != nil {
		t.Fatalf("build blocking config: %v", err)
	}

	assertSameLists(t, "denylists", flattenLists(cfg.Blocking.Denylists), flattenLists(got.Denylists))
	assertSameLists(t, "allowlists", flattenLists(cfg.Blocking.Allowlists), flattenLists(got.Allowlists))
	assertSameLists(t, "clientGroupsBlock", cfg.Blocking.ClientGroupsBlock, got.ClientGroupsBlock)

	if got.BlockType != cfg.Blocking.BlockType {
		t.Errorf("blockType: want %q, got %q", cfg.Blocking.BlockType, got.BlockType)
	}

	if got.BlockTTL != cfg.Blocking.BlockTTL {
		t.Errorf("blockTTL: want %s, got %s", cfg.Blocking.BlockTTL, got.BlockTTL)
	}
}

// A file source must come back as a file source. dbSourceToBytes falls back to
// text for anything it does not recognise, so a wrong type name here would turn
// an unreadable path into an empty inline list and block nothing, quietly.
func TestSeedBlockingPreservesSourceTypes(t *testing.T) {
	_, store := seedTestStore(t, `
		blocking:
		  denylists:
		    mixed:
		      - http://httpserver:8080/list.txt
		      - /etc/blocky/local.txt
		  clientGroupsBlock:
		    default:
		      - mixed
		`)

	got, err := store.BuildBlockingConfig(config.Blocking{})
	if err != nil {
		t.Fatalf("build blocking config: %v", err)
	}

	want := []string{
		config.BytesSourceTypeHttp.String() + ":http://httpserver:8080/list.txt",
		config.BytesSourceTypeFile.String() + ":/etc/blocky/local.txt",
	}

	if gotSources := flattenLists(got.Denylists)["mixed"]; !slices.Equal(want, gotSources) {
		t.Errorf("denylist sources: want %v, got %v", want, gotSources)
	}
}

// blockType and blockTTL are singletons with a non-empty default on both sides,
// so an unseeded store silently answers with its own default rather than the
// fixture's — which is how eight blockType/blockTTL specs failed.
func TestSeedBlockingOverridesTheStoreDefaults(t *testing.T) {
	for _, blockType := range []string{"zeroIP", "nxDomain", "refused", "192.168.1.1,2001:db8::1"} {
		t.Run(blockType, func(t *testing.T) {
			_, store := seedTestStore(t, fmt.Sprintf(`
				blocking:
				  denylists:
				    ads:
				      - http://httpserver:8080/list.txt
				  clientGroupsBlock:
				    default:
				      - ads
				  blockType: %s
				  blockTTL: 2m
				`, blockType))

			got, err := store.BuildBlockingConfig(config.Blocking{})
			if err != nil {
				t.Fatalf("build blocking config: %v", err)
			}

			if got.BlockType != blockType {
				t.Errorf("blockType: want %q, got %q", blockType, got.BlockType)
			}

			if want := config.Duration(2 * 60 * 1e9); got.BlockTTL != want {
				t.Errorf("blockTTL: want %s, got %s", want, got.BlockTTL)
			}
		})
	}
}

func TestSeedCustomDNSRoundTripsThroughTheOverlay(t *testing.T) {
	cfg, store := seedTestStore(t, `
		customDNS:
		  customTTL: 30m
		  mapping:
		    printer.lan: 192.168.178.3
		    otherdevice.lan: 192.168.178.15,2001:0db8:85a3:08d3:1319:8a2e:0370:7344
		`)

	got, err := store.BuildCustomDNSConfig(config.CustomDNS{})
	if err != nil {
		t.Fatalf("build custom DNS config: %v", err)
	}

	assertSameLists(t, "mapping", flattenMapping(cfg.CustomDNS.Mapping), flattenMapping(got.Mapping))
}
