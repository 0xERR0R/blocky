package e2e

import (
	"fmt"
	"strings"
	"testing"
)

// These are plain Go tests, not Ginkgo specs, so they run in the fast CI job
// rather than behind the `e2e` label — no container runtime needed. They guard
// the seed bridge's parsing, which is the part that fails silently: a fixture
// whose sections are dropped still starts a healthy-looking container, it just
// runs on defaults.

func TestSplitYAMLLinesRescuesAWholeDocumentInOneElement(t *testing.T) {
	// dedent trims the leading newline, so a whole document passed as a single
	// variadic element begins with "upstreams:" — which extractUpstreamYAML
	// prefix-matches, and then drops the element entirely, taking every other
	// section with it. The cap-drop spec was written this way and silently ran
	// on port 53 against the store's built-in upstreams for as long as the e2e
	// suite went unrun.
	lines := []string{dedent(fmt.Sprintf(`
		upstreams:
		  groups:
		    default:
		      - moka1
		ports:
		  dns: %d
		`, 4053))}

	seed, stripped := extractUpstreamYAML(splitYAMLLines(lines))

	if got := strings.Join(seed.groupOrder, ","); got != "default" {
		t.Errorf("upstream groups: want %q, got %q", "default", got)
	}

	if got := seed.groups["default"]; len(got) != 1 || got[0] != "moka1" {
		t.Errorf("default group servers: want [moka1], got %v", got)
	}

	out := strings.Join(ensureDatabasePath(stripped, containerConfigDBPath), "\n")

	for _, want := range []string{"ports:", "dns: 4053", "databasePath: " + containerConfigDBPath} {
		if !strings.Contains(out, want) {
			t.Errorf("config should retain %q, got:\n%s", want, out)
		}
	}

	if strings.Contains(out, "upstreams:") {
		t.Errorf("upstreams: must be stripped for the YAML loader to accept the config, got:\n%s", out)
	}
}

func TestSplitYAMLLinesLeavesAlreadySplitInputAlone(t *testing.T) {
	lines := strings.Split(dedent(`
		upstreams:
		  groups:
		    default:
		      - moka1
		blocking:
		  blockType: nxDomain
		`), "\n")

	seed, stripped := extractUpstreamYAML(splitYAMLLines(lines))

	if got := strings.Join(seed.groupOrder, ","); got != "default" {
		t.Errorf("upstream groups: want %q, got %q", "default", got)
	}

	out := strings.Join(stripped, "\n")
	if !strings.Contains(out, "blockType: nxDomain") {
		t.Errorf("config should retain the blocking section, got:\n%s", out)
	}
}

func TestEnsureDatabasePathDoesNotOverrideTheFixture(t *testing.T) {
	lines := []string{"databasePath: /custom/path.db"}

	out := strings.Join(ensureDatabasePath(lines, containerConfigDBPath), "\n")
	if out != "databasePath: /custom/path.db" {
		t.Errorf("an explicit databasePath must win, got %q", out)
	}
}
