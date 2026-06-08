package util

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// FuzzParseIPFromArpaAddr exercises ParseIPFromArpaAddr, which parses reverse-DNS
// (PTR) names taken directly off the network, with arbitrary input. However
// malformed the name is, parsing must never panic.
func FuzzParseIPFromArpaAddr(f *testing.F) {
	for _, s := range []string{
		"", "in-addr.arpa.", "ip6.arpa.",
		"8.8.8.8.in-addr.arpa.",
		"1.0.0.127.in-addr.arpa.",
		"x.8.8.8.in-addr.arpa.",
		"256.8.8.8.in-addr.arpa.",
		"4.3.2.1.0.d.d.4.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		_, _ = ParseIPFromArpaAddr(in) // must not panic
	})
}

// FuzzParseIPFromArpaAddrRoundtrip cross-checks ParseIPFromArpaAddr against
// dns.ReverseAddr (from miekg/dns, already a dependency) as an oracle: for any
// valid IPv4 or IPv6 address, the arpa name produced by ReverseAddr must parse
// back to the same address.
func FuzzParseIPFromArpaAddrRoundtrip(f *testing.F) {
	f.Add([]byte{8, 8, 8, 8})
	f.Add([]byte{127, 0, 0, 1})
	f.Add([]byte(net.ParseIP("2001:db8::1").To16()))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var ip net.IP

		switch len(raw) {
		case net.IPv4len:
			ip = net.IPv4(raw[0], raw[1], raw[2], raw[3])
		case net.IPv6len:
			ip = net.IP(raw).To16()
		default:
			return // only 4- and 16-byte inputs map to a concrete IP
		}

		arpa, err := dns.ReverseAddr(ip.String())
		if err != nil {
			t.Fatalf("dns.ReverseAddr(%s) failed: %v", ip, err)
		}

		got, err := ParseIPFromArpaAddr(arpa)
		if err != nil {
			t.Fatalf("ParseIPFromArpaAddr(%q) failed for ip %s: %v", arpa, ip, err)
		}

		if !got.Equal(ip) {
			t.Fatalf("round-trip mismatch: ip %s -> arpa %q -> %s", ip, arpa, got)
		}
	})
}
