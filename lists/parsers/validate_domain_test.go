package parsers

import (
	"regexp"
	"strings"
	"testing"
)

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
