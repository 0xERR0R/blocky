package parsers

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/idna"
)

// Plain table + fuzz tests for the helper functions in hosts.go. They live in a
// separate file from the Ginkgo behaviour suite (hosts_test.go) because Fuzz
// targets cannot be expressed as Ginkgo It blocks.

// --- domain name validation (isValidDomainName) ---

// legacyDomainNameRegex is the exact regexp that isValidDomainName replaced.
// These tests assert the hand-rolled validator is equivalent to it.
var legacyDomainNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,63}(\.[a-zA-Z0-9_-]{1,63})*[\._]?$`)

func TestIsValidDomainName_MatchesLegacyRegex(t *testing.T) {
	cases := []string{
		"", "a", "-", "_", ".", "..", "...",
		"example.com", "example.com.", "example.com_",
		"a.b._", "a..b", "a.", "a._", "._", "_.", "a_",
		"-leading-hyphen.example.com", "trailing-hyphen-.example.com",
		"under_score.example.org",
		"sub.domain.with-hyphen.example.com",
		"xn--mnchen-3ya.example.de",
		"192.168.1.1", "::1",
		"foo bar", "foo\tbar", "foo*bar", "foo#bar",
		strings.Repeat("a", 63), strings.Repeat("a", 64),
		strings.Repeat("a", 63) + ".com", strings.Repeat("a", 64) + ".com",
		strings.Repeat("a", 63) + "_", strings.Repeat("a", 63) + ".",
		"a." + strings.Repeat("b", 64),
	}

	for _, in := range cases {
		want := legacyDomainNameRegex.MatchString(in)
		if got := isValidDomainName(in); got != want {
			t.Errorf("isValidDomainName(%q) = %v, want %v (legacy regex)", in, got, want)
		}
	}
}

// FuzzIsValidDomainName proves equivalence with the legacy regex for arbitrary input.
func FuzzIsValidDomainName(f *testing.F) {
	for _, s := range []string{"example.com", "a.b._", strings.Repeat("a", 64), "a..b", "_-.", ""} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		want := legacyDomainNameRegex.MatchString(in)
		if got := isValidDomainName(in); got != want {
			t.Errorf("isValidDomainName(%q) = %v, want %v (legacy regex)", in, got, want)
		}
	})
}

// --- entry normalization (normalizeHostsListEntry) ---

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

// --- IP pre-check (MightBeIP) ---

func TestMightBeIP_NeverSkipsRealIP(t *testing.T) {
	cases := []string{
		"", "example.com", "0.0.0.0", "127.0.0.1", "192.168.178.55",
		"::1", "2001:db8::1", "0:0:0:0:0:0:0:1", "::ffff:1.2.3.4",
		"fe80::1", "deadbeef", "abc.def", "1.example.com", "g.com",
		"DEAD::BEEF", "not-an-ip", "256.256.256.256",
	}

	for _, s := range cases {
		isIP := net.ParseIP(s) != nil
		if isIP && !MightBeIP(s) {
			t.Errorf("MightBeIP(%q) = false but net.ParseIP accepts it", s)
		}
	}
}

// FuzzMightBeIP asserts the safety invariant: MightBeIP never returns false for
// a string that net.ParseIP would accept (so gating ParseIP behind it is safe).
func FuzzMightBeIP(f *testing.F) {
	for _, s := range []string{"1.2.3.4", "::1", "2001:db8::1", "example.com", ""} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		if net.ParseIP(s) != nil && !MightBeIP(s) {
			t.Errorf("MightBeIP(%q) = false but net.ParseIP accepts it", s)
		}
	})
}

// --- entry parsing (HostListEntry / HostsFileEntry / HostsIterator) ---

// FuzzHostsUnmarshalText feeds arbitrary input to the hosts-list parsers, which
// consume untrusted downloaded block/allow lists line by line. Neither the
// individual entry types nor the HostsIterator that dispatches between them may
// panic on any input.
//
// Beyond the no-panic guarantee it asserts the post-conditions the parsers
// document:
//   - a successful HostsFileEntry has a non-nil IP and only valid host names;
//   - HostListEntry normalization is idempotent: re-parsing its own output is a
//     fixpoint, since a normalized entry is already in canonical form.
func FuzzHostsUnmarshalText(f *testing.F) {
	for _, s := range []string{
		"example.com",
		"||ads.example.com^",
		"0.0.0.0 ads.example.com",
		"127.0.0.1 localhost local.host",
		"::1 ip6-localhost",
		"fe80::1%eth0 router.local",
		"*.tracker.example.com",
		`/^ads\.example\.com$/`,
		"münchen.example.de",
		"xn--mnchen-3ya.example.de",
		"", " ", "\t", "1.2.3.4",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		data := []byte(in)

		// None of the parsers may panic, regardless of whether they accept the input.
		var list HostListEntry
		listErr := list.UnmarshalText(data)

		var file HostsFileEntry
		fileErr := file.UnmarshalText(data)

		var iter HostsIterator
		_ = iter.UnmarshalText(data)

		// A successful hosts-file entry must carry a usable IP and valid names.
		if fileErr == nil {
			if file.IP == nil {
				t.Fatalf("HostsFileEntry parsed %q but IP is nil", in)
			}

			_ = file.forEachHost(func(host string) error {
				if err := validateDomainName(host); err != nil {
					t.Fatalf("HostsFileEntry parsed %q but emitted host %q is invalid: %v", in, host, err)
				}

				return nil
			})
		}

		// Normalizing an already-normalized host-list entry must be a fixpoint.
		if listErr == nil {
			var reparsed HostListEntry
			if err := reparsed.UnmarshalText([]byte(list.String())); err != nil {
				t.Fatalf("HostListEntry %q normalized to %q which fails to re-parse: %v", in, list.String(), err)
			}

			if reparsed != list {
				t.Fatalf("HostListEntry normalization is not idempotent: %q -> %q -> %q", in, list.String(), reparsed.String())
			}
		}
	})
}
