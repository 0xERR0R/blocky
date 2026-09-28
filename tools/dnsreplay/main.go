// Command dnsreplay fires a fixed DNS query matrix at a running Blockasaurus
// instance and prints a canonical, diffable dump of every answer.
//
// It exists so that "did the upstream merge change what we answer?" is settled
// by diffing two captures rather than by remembering. Run it against the old
// binary and the new one, both seeded with the same config store, and diff:
//
//	go run ./tools/dnsreplay 127.0.0.1:55351 > before.txt
//	go run ./tools/dnsreplay 127.0.0.1:55352 > after.txt
//	diff -u before.txt after.txt
//
// The matrix covers the paths docs/UPSTREAM_SYNC.md §5 Phase 7 calls for:
// blocked, allowlisted, custom DNS, conditional forwarding, DNSSEC, EDNS0 and
// the fqdnOnly filter. The seeding the capture expects is described in
// docs/upstream-sync/behavioral-replay-2026-09.md.
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	exchangeTimeout = 8 * time.Second

	// advertisedUDPSize is the EDNS0 buffer size every OPT-bearing probe
	// advertises. Fixed rather than varied: the point of these probes is
	// whether an OPT comes back at all, not buffer negotiation.
	advertisedUDPSize = 4096
)

// Names the probe matrix reuses. They correspond to the config-store seeding
// described in docs/upstream-sync/behavioral-replay-2026-09.md.
const (
	blocked    = "blocked-domain.test."
	customA    = "printer.lan."
	upstreamA  = "example.com."
	singleLbl  = "singlelabel."
	signedZone = "cloudflare.com."
)

type probe struct {
	name     string
	qname    string
	qtype    uint16
	do       bool   // DNSSEC OK bit, implies edns
	edns     bool   // attach OPT
	cookie   string // client cookie hex, implies edns
	tcp      bool
	volatile bool // answer content depends on the live internet; record shape only
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: dnsreplay <host:port>")
		os.Exit(2)
	}

	addr := os.Args[1]

	probes := []probe{
		{name: "blocked/denylist A", qname: blocked, qtype: dns.TypeA},
		{name: "blocked/denylist AAAA", qname: blocked, qtype: dns.TypeAAAA},
		{name: "blocked/subdomain A", qname: "sub." + blocked, qtype: dns.TypeA},
		{name: "blocked/second entry A", qname: "ads.example.net.", qtype: dns.TypeA},
		{name: "allowlist beats denylist A", qname: "allowed.example.net.", qtype: dns.TypeA, volatile: true},
		{name: "customdns A", qname: customA, qtype: dns.TypeA},
		{name: "customdns unmapped type AAAA", qname: customA, qtype: dns.TypeAAAA},
		{name: "customdns unmapped type TXT", qname: customA, qtype: dns.TypeTXT},
		{name: "customdns subdomain A", qname: "sub." + customA, qtype: dns.TypeA},
		{name: "customdns dual-stack A", qname: "dual.lan.", qtype: dns.TypeA},
		{name: "customdns dual-stack AAAA", qname: "dual.lan.", qtype: dns.TypeAAAA},
		{name: "conditional forward A", qname: "fritz.box.", qtype: dns.TypeA, volatile: true},
		{name: "conditional subdomain A", qname: "host.fritz.box.", qtype: dns.TypeA, volatile: true},
		{name: "upstream resolved A", qname: upstreamA, qtype: dns.TypeA, volatile: true},
		{name: "upstream resolved AAAA", qname: upstreamA, qtype: dns.TypeAAAA, volatile: true},
		{name: "upstream NXDOMAIN", qname: "nx-blockasaurus-replay." + upstreamA, qtype: dns.TypeA, volatile: true},
		{name: "fqdnOnly single label", qname: singleLbl, qtype: dns.TypeA},
		{name: "fqdnOnly single label AAAA", qname: singleLbl, qtype: dns.TypeAAAA},
		{name: "edns0 plain OPT on blocked", qname: blocked, qtype: dns.TypeA, edns: true},
		{name: "edns0 plain OPT on customdns", qname: customA, qtype: dns.TypeA, edns: true},
		{name: "edns0 plain OPT on notfqdn", qname: singleLbl, qtype: dns.TypeA, edns: true},
		{name: "edns0 cookie passthrough", qname: upstreamA, qtype: dns.TypeA,
			cookie: "0102030405060708", volatile: true},
		{name: "dnssec DO signed zone", qname: signedZone, qtype: dns.TypeA, do: true, volatile: true},
		{name: "dnssec DO unsigned zone", qname: "example.org.", qtype: dns.TypeA, do: true, volatile: true},
		{name: "dnssec DO on blocked", qname: blocked, qtype: dns.TypeA, do: true},
		{name: "dnssec DNSKEY", qname: signedZone, qtype: dns.TypeDNSKEY, do: true, volatile: true},
		{name: "tcp blocked A", qname: blocked, qtype: dns.TypeA, tcp: true},
		{name: "tcp customdns A", qname: customA, qtype: dns.TypeA, tcp: true},
		{name: "large response compression", qname: signedZone, qtype: dns.TypeANY,
			edns: true, tcp: true, volatile: true},
	}

	for _, p := range probes {
		fmt.Printf("### %s  [%s %s]\n", p.name, p.qname, dns.TypeToString[p.qtype])
		fmt.Println(run(addr, p))
		fmt.Println()
	}
}

func run(addr string, p probe) string {
	m := new(dns.Msg)
	m.SetQuestion(p.qname, p.qtype)
	m.RecursionDesired = true

	if p.edns || p.do || p.cookie != "" {
		o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		o.SetUDPSize(advertisedUDPSize)
		if p.do {
			o.SetDo()
		}
		if p.cookie != "" {
			o.Option = append(o.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: p.cookie})
		}
		m.Extra = append(m.Extra, o)
	}

	c := &dns.Client{Timeout: exchangeTimeout}
	if p.tcp {
		c.Net = "tcp"
	}

	r, _, err := c.Exchange(m, addr)
	if err != nil {
		return "  ERROR: " + err.Error()
	}

	var b strings.Builder

	fmt.Fprintf(&b, "  rcode=%s flags=[%s] counts=an:%d,ns:%d,ar:%d\n",
		dns.RcodeToString[r.Rcode], flags(r), len(r.Answer), len(r.Ns), len(r.Extra))

	fmt.Fprintf(&b, "  ANSWER:\n%s", section(r.Answer, p.volatile))
	fmt.Fprintf(&b, "  AUTHORITY:\n%s", section(r.Ns, p.volatile))
	fmt.Fprintf(&b, "  ADDITIONAL:\n%s", section(r.Extra, p.volatile))

	return strings.TrimRight(b.String(), "\n")
}

func flags(m *dns.Msg) string {
	var f []string
	for _, x := range []struct {
		on bool
		s  string
	}{
		{m.Response, "qr"}, {m.Authoritative, "aa"}, {m.Truncated, "tc"},
		{m.RecursionDesired, "rd"}, {m.RecursionAvailable, "ra"},
		{m.AuthenticatedData, "ad"}, {m.CheckingDisabled, "cd"},
	} {
		if x.on {
			f = append(f, x.s)
		}
	}

	return strings.Join(f, " ")
}

// section renders one message section. For volatile probes the record data is
// dropped and only the type shape is kept, so live-internet churn between two
// runs does not read as a merge regression.
func section(rrs []dns.RR, volatile bool) string {
	if len(rrs) == 0 {
		return "    (empty)\n"
	}

	out := make([]string, 0, len(rrs))

	for _, rr := range rrs {
		h := rr.Header()
		if opt, ok := rr.(*dns.OPT); ok {
			out = append(out, fmt.Sprintf("    OPT udpsize=%d do=%t options=%s",
				opt.UDPSize(), opt.Do(), optNames(opt)))

			continue
		}

		if volatile {
			out = append(out, fmt.Sprintf("    %s %s %s", dns.TypeToString[h.Rrtype], h.Name, rdataClass(rr)))

			continue
		}

		out = append(out, "    "+normalizeSOA(rr))
	}

	sort.Strings(out)

	return strings.Join(out, "\n") + "\n"
}

// rdataClass keeps a volatile record diffable without pinning live rdata: a
// blocking sentinel (0.0.0.0 / ::) is reported as such, because the whole
// point of the replay is to notice a name that changes between blocked and
// resolved. Anything else is just "live".
func rdataClass(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		if v.A.IsUnspecified() {
			return "<blocked-sentinel>"
		}
	case *dns.AAAA:
		if v.AAAA.IsUnspecified() {
			return "<blocked-sentinel>"
		}
	}

	return "<live>"
}

// normalizeSOA strips the serial from a SOA, which is minted from the clock in
// some synthesized responses and would otherwise differ on every run.
func normalizeSOA(rr dns.RR) string {
	soa, ok := rr.(*dns.SOA)
	if !ok {
		return rr.String()
	}

	c := *soa
	c.Serial = 0

	return c.String()
}

func optNames(o *dns.OPT) string {
	if len(o.Option) == 0 {
		return "none"
	}

	names := make([]string, 0, len(o.Option))
	for _, e := range o.Option {
		names = append(names, strconv.FormatUint(uint64(e.Option()), 10))
	}

	sort.Strings(names)

	return strings.Join(names, ",")
}
