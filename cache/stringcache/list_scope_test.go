package stringcache

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/0xERR0R/blocky/lists/parsers"
)

// TestListEntriesCannotWidenScope runs list lines through the production parser
// and cache chain and checks that malformed entries are rejected instead of
// being cached as a broader rule. "*.com.xn--" once normalized to "*.com.",
// which the wildcard cache folded into a rule matching every .com name, and no
// parse error was raised for it, so the error allowance never saw it.
func TestListEntriesCannotWidenScope(t *testing.T) {
	const group = "g"

	malformed := []string{
		"*.com.xn--",
		"*.com.\u00ad", // soft hyphen only: an ignored code point
		"*.xn--.com",
		"*.\u200b.com",    // zero-width space only
		"*.com\u3002xn--", // ideographic full stop as the separator
		"*..com",
		"*.",
		"com.xn--",
		"0.0.0.0 com.xn--",
	}

	legitimate := []string{
		"*.example.org.",
		"*.münchen.example.de",
		"münchen.example.de",
	}

	lines := strings.Join(append(append([]string{}, malformed...), legitimate...), "\n") + "\n"

	var errs []string

	p := parsers.AllowErrors(parsers.Hosts(strings.NewReader(lines)), parsers.NoErrorLimit)
	p.OnErr(func(err error) { errs = append(errs, err.Error()) })

	chain := NewChainedGroupedCache(
		NewInMemoryGroupedRegexCache(), NewInMemoryGroupedWildcardCache(), NewInMemoryGroupedStringCache(),
	)
	factory := chain.Refresh(group)

	err := parsers.ForEach(context.Background(), p, func(entry *parsers.HostsIterator) error {
		return entry.ForEach(func(host string) error {
			factory.AddEntry(host)

			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	factory.Finish()

	if len(errs) != len(malformed) {
		t.Fatalf("expected %d parse errors, got %d:\n%s", len(malformed), len(errs), strings.Join(errs, "\n"))
	}

	for i, e := range errs {
		if want := fmt.Sprintf("line %d: ", i+1); !strings.HasPrefix(e, want) {
			t.Errorf("error %d does not carry its line position: %s", i, e)
		}
	}

	for _, name := range []string{"example.com", "com", "sub.example.com"} {
		if got := chain.Contains(name, []string{group}); len(got) != 0 {
			t.Errorf("%q matched %v, a malformed entry widened the rules", name, got)
		}
	}

	for _, name := range []string{"sub.example.org", "sub.xn--mnchen-3ya.example.de", "xn--mnchen-3ya.example.de"} {
		if got := chain.Contains(name, []string{group}); len(got) == 0 {
			t.Errorf("%q did not match, a legitimate entry was lost", name)
		}
	}
}
