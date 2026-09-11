package parsers

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
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

// normalizeReference is normalizeHostsListEntry without the ASCII fast-path:
// every non-regex entry goes through idnaProfile. The fast-path must be
// equivalent to it for every input: same error presence, and the same host up
// to ASCII case (the IDNA mapping lowercases, the fast-path leaves case to the
// caches, which fold it).
func normalizeReference(host string) (string, error) {
	host = strings.TrimPrefix(host, "||")
	host = strings.TrimSuffix(host, "^")

	if ip, ok := unwrapIPv6Literal(host); ok {
		return ip, nil
	}

	if !isRegex(host) {
		var err error

		host, err = idnaProfile.ToASCII(host)
		if err != nil {
			return "", fmt.Errorf("%w: %s", err, host)
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
		"a.b.c", "single", "192.168.1.1", "DEAD::BEEF",
		// IPv6 literals
		"[2001:db8::1]", "||[::1]^", "[::ffff:1.2.3.4]",
		"[1.2.3.4]", "[example.com]", "[::1", "::1]", "[]", "[", "[fe80::1%eth0]", "[::1]:53",
		// ABP markers
		"||abp.example.com^", "||abp.example.org",
		// regex (IDNA always skipped)
		"/^ads\\.example\\.com$/", "/café/", "/[A-Z]+/",
		// already-encoded punycode (ASCII)
		"xn--mnchen-3ya.example.de", "xn--bcher-kva.example.com",
		"XN--MNCHEN-3YA.example.de", "xn--invalid!!.example.com", "xn--",
		// Unicode (must go through IDNA)
		"münchen.example.de", "bücher.example.com", "пример.example.com",
		"日本語.example.jp", "café.example.fr",
		"MÜNCHEN.example.de", "u\u0308ber.example.de", "ｅｘａｍｐｌｅ.com", "ẞ.example.de",
		// mixed punycode + Unicode (the subtle case)
		"xn--mnchen-3ya.café.com", "café.xn--mnchen-3ya.com",
		// Unicode with ABP markers
		"||münchen.example.de^",
		// junk that must stay rejected
		"dGVzdA==", "YWJj+/==", "münchen..de", "\xff.example.com",
	}

	for _, in := range inputs {
		gotHost, gotErr := normalizeHostsListEntry(in)
		wantHost, wantErr := normalizeReference(in)

		if !strings.EqualFold(gotHost, wantHost) || (gotErr == nil) != (wantErr == nil) {
			t.Errorf("normalizeHostsListEntry(%q) = (%q, err=%v); reference = (%q, err=%v)",
				in, gotHost, gotErr, wantHost, wantErr)
		}
	}
}

// FuzzNormalizeHostsListEntry checks the fast-path matches the reference for
// arbitrary input (host value up to ASCII case, and error presence).
func FuzzNormalizeHostsListEntry(f *testing.F) {
	for _, s := range []string{
		"example.com", "Example.COM", "münchen.de", "MÜNCHEN.de", "xn--mnchen-3ya.de", "xn--a.café.com",
		"||x^", "/r/", "[::1]", "||[2001:db8::1]^", "[x]",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		gotHost, gotErr := normalizeHostsListEntry(in)
		wantHost, wantErr := normalizeReference(in)

		if !strings.EqualFold(gotHost, wantHost) || (gotErr == nil) != (wantErr == nil) {
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
		"*.münchen.example.de",
		`/^ads\.example\.com$/`,
		"münchen.example.de",
		"MÜNCHEN.example.de",
		"xn--mnchen-3ya.example.de",
		"0.0.0.0 münchen.example.de",
		"[2001:db8::1]",
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
