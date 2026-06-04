package parsers

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/net/idna"
)

// normalizeReference is a verbatim copy of normalizeHostsListEntry as it was
// before the ASCII fast-path was added. The fast-path must be equivalent to it
// for every input (both the returned host and whether an error occurred).
func normalizeReference(host string) (string, error) {
	var err error

	var hostUnicode string

	idnaProfile := idna.Punycode

	host = strings.TrimPrefix(host, "||")
	host = strings.TrimSuffix(host, "^")

	if !isRegex(host) {
		hostUnicode, err = idnaProfile.ToUnicode(host)
		if err != nil || hostUnicode == host {
			host, err = idnaProfile.ToASCII(host)
			if err != nil {
				return "", fmt.Errorf("%w: %s", err, host)
			}
		}
	}

	if err := validateHostsListEntry(host); err != nil {
		return "", err
	}

	return host, nil
}

func TestNormalizeHostsListEntry_MatchesReference(t *testing.T) {
	inputs := []string{
		// pure ASCII (fast-path skips IDNA)
		"example.com", "Example.COM", "under_score.example.org",
		"trailing.dot.example.com.", "-leading.example.com",
		"a.b.c", "single", "192.168.1.1",
		// ABP markers
		"||abp.example.com^", "||abp.example.org",
		// regex (IDNA always skipped)
		"/^ads\\.example\\.com$/", "/café/",
		// already-encoded punycode (ASCII)
		"xn--mnchen-3ya.example.de", "xn--bcher-kva.example.com",
		"xn--invalid!!.example.com",
		// Unicode (must go through IDNA)
		"münchen.example.de", "bücher.example.com", "пример.example.com",
		"日本語.example.jp", "café.example.fr",
		// mixed punycode + Unicode (the subtle case)
		"xn--mnchen-3ya.café.com", "café.xn--mnchen-3ya.com",
		// Unicode with ABP markers
		"||münchen.example.de^",
	}

	for _, in := range inputs {
		gotHost, gotErr := normalizeHostsListEntry(in)
		wantHost, wantErr := normalizeReference(in)

		if gotHost != wantHost || (gotErr == nil) != (wantErr == nil) {
			t.Errorf("normalizeHostsListEntry(%q) = (%q, err=%v); reference = (%q, err=%v)",
				in, gotHost, gotErr, wantHost, wantErr)
		}
	}
}

// FuzzNormalizeHostsListEntry checks the fast-path matches the reference for
// arbitrary input (host value and error presence).
func FuzzNormalizeHostsListEntry(f *testing.F) {
	for _, s := range []string{"example.com", "münchen.de", "xn--mnchen-3ya.de", "xn--a.café.com", "||x^", "/r/"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		gotHost, gotErr := normalizeHostsListEntry(in)
		wantHost, wantErr := normalizeReference(in)

		if gotHost != wantHost || (gotErr == nil) != (wantErr == nil) {
			t.Errorf("normalizeHostsListEntry(%q) = (%q, err=%v); reference = (%q, err=%v)",
				in, gotHost, gotErr, wantHost, wantErr)
		}
	})
}
