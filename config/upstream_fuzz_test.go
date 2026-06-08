package config

import "testing"

// FuzzParseUpstream exercises ParseUpstream with arbitrary input. The function
// parses untrusted upstream specifications, including DNS stamps (sdns://...)
// whose payload is base64-decoded and then sliced by an attacker-controlled
// length byte in stampWithoutAddrPort. The core invariant is therefore that it
// must never panic, no matter how malformed the input is.
//
// For a successfully parsed *non-stamp* upstream it additionally asserts that
// String() is a parse fixpoint: re-parsing u.String() succeeds and yields the
// same String(). Stamps are exempt because String() intentionally omits stamp
// metadata (certificate fingerprints, bootstrap IPs, common name), so a
// round-trip through it is lossy by design.
func FuzzParseUpstream(f *testing.F) {
	seeds := []string{
		"", ":53", "udp",
		"8.8.8.8:5353",
		"[2001:4860:4860::8888]:5353",
		"tcp-tls:dns.example.com:853",
		"https://dns.example.com:8443/dns-query",
		"quic://dns.adguard.com",
		"dns.example.com#cloudflare-dns.com",
		// DNS stamps, including a deliberately malformed one (invalid..hostname).
		"sdns://",
		"sdns://AAcAAAAAAAAABzguOC44Ljg",
		"sdns://AgcAAAAAAAAABzEuMC4wLjEAEWludmFsaWQuLmhvc3RuYW1lCi9kbnMtcXVlcnk",
		"sdns://AwAAAAAAAAAADTE0OS4xMTIuMTEyLjkgIINqrLwxXg3E7t8E8DTYfvzaJI-U3WvkQgHQj8JBJgkJcXVhZDkubmV0",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		u, err := ParseUpstream(in)
		if err != nil {
			return // rejecting input is fine; we only require that it not panic
		}

		// String() is lossy for stamps by design, so the fixpoint check below
		// does not apply to them.
		if isDNSStamp(in) {
			return
		}

		s1 := u.String()

		u2, err := ParseUpstream(s1)
		if err != nil {
			t.Fatalf("ParseUpstream(%q) succeeded but re-parsing its String() %q failed: %v", in, s1, err)
		}

		if s2 := u2.String(); s2 != s1 {
			t.Fatalf("String() is not a fixpoint for input %q: first %q, second %q", in, s1, s2)
		}
	})
}
