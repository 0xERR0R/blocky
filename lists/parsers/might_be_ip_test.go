package parsers

import (
	"net"
	"testing"
)

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
