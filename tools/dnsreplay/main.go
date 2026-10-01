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
// It exits non-zero if any probe got no answer, so a capture taken against a
// port nothing is listening on cannot be mistaken for a clean one.
//
// The matrix covers the paths docs/UPSTREAM_SYNC.md §5 Phase 7 calls for:
// blocked, allowlisted, custom DNS, conditional forwarding, DNSSEC, EDNS0 and
// the fqdnOnly filter. The seeding it expects, and what it deliberately does
// not cover, are described in
// docs/upstream-sync/behavioral-replay-2026-09.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"slices"
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

	// repeatGap separates the two halves of a ttlCountdown probe. Long
	// enough that a counting-down TTL is unambiguous, short enough not to
	// slow the capture down noticeably.
	repeatGap = 4 * time.Second
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
	name   string
	qname  string
	qtype  uint16
	do     bool   // DNSSEC OK bit, implies edns
	edns   bool   // attach OPT
	cookie string // client cookie hex, implies edns
	tcp    bool

	// volatile marks a probe whose answer comes from the live internet.
	// Its rdata is replaced by a classification so upstream churn between
	// two runs does not read as a merge regression — see rdataClass.
	volatile bool

	// ttlCountdown asks the same question twice, repeatGap apart, and
	// reports whether the authority TTL decreased instead of printing the
	// answer. This is the only probe shape that can observe upstream
	// 190d512 (count down cached authority/additional TTLs); a
	// single-shot capture cannot.
	ttlCountdown bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dnsreplay:", err)
		os.Exit(1)
	}
}

func run() error {
	blockIPs := flag.String("block-ip", "0.0.0.0,::",
		"comma-separated address(es) the instance answers blocked queries with; a volatile "+
			"probe returning one of these is reported as blocked rather than live. Must match "+
			"the instance's blockType when that is a custom IP.")

	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), "usage: dnsreplay [flags] <host:port>\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()

		return errors.New("exactly one <host:port> argument is required")
	}

	sentinels, err := parseSentinels(*blockIPs)
	if err != nil {
		return err
	}

	addr := flag.Arg(0)
	probes := matrix()

	var failed int

	for _, p := range probes {
		fmt.Printf("### %s  [%s %s]\n", p.name, p.qname, dns.TypeToString[p.qtype])

		out, probeErr := runProbe(addr, p, sentinels)
		if probeErr != nil {
			failed++

			fmt.Printf("  ERROR: %s\n", classifyErr(probeErr))
		} else {
			fmt.Println(out)
		}

		fmt.Println()
	}

	// Any unanswered probe is worth a non-zero exit: in the capture-and-diff
	// workflow a wrong port or a server that never came up would otherwise
	// produce a file that looks like output. A genuine no-answer is also a
	// finding in its own right — the pre-merge tree did exactly that on the
	// fqdnOnly probes — so the message says which case to check for rather
	// than declaring the capture worthless.
	switch {
	case failed == len(probes):
		return fmt.Errorf("all %d probes got no answer — is anything listening on %s?",
			failed, addr)
	case failed > 0:
		return fmt.Errorf("%d of %d probes got no answer; see the ERROR lines — "+
			"that is a finding if the server is up, and a broken capture if it is not",
			failed, len(probes))
	}

	return nil
}

func matrix() []probe {
	return []probe{
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
		{
			name: "edns0 cookie passthrough", qname: upstreamA, qtype: dns.TypeA,
			cookie: "0102030405060708", volatile: true,
		},
		{name: "dnssec DO signed zone", qname: signedZone, qtype: dns.TypeA, do: true, volatile: true},
		{name: "dnssec DO unsigned zone", qname: "example.org.", qtype: dns.TypeA, do: true, volatile: true},
		{name: "dnssec DO on blocked", qname: blocked, qtype: dns.TypeA, do: true},
		{name: "dnssec DNSKEY", qname: signedZone, qtype: dns.TypeDNSKEY, do: true, volatile: true},
		{name: "tcp blocked A", qname: blocked, qtype: dns.TypeA, tcp: true},
		{name: "tcp customdns A", qname: customA, qtype: dns.TypeA, tcp: true},
		{
			name: "cached authority TTL counts down", qname: "aaaa-only-nx.example.net.",
			qtype: dns.TypeAAAA, ttlCountdown: true,
		},
	}
}

func parseSentinels(list string) ([]net.IP, error) {
	var out []net.IP

	for s := range strings.SplitSeq(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("-block-ip: %q is not an IP address", s)
		}

		out = append(out, ip)
	}

	return out, nil
}

func runProbe(addr string, p probe, sentinels []net.IP) (string, error) {
	first, err := exchange(addr, p)
	if err != nil {
		return "", err
	}

	if !p.ttlCountdown {
		return render(first, p, sentinels), nil
	}

	time.Sleep(repeatGap)

	second, err := exchange(addr, p)
	if err != nil {
		return "", err
	}

	return renderCountdown(first, second), nil
}

func exchange(addr string, p probe) (*dns.Msg, error) {
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

	return r, err
}

func render(r *dns.Msg, p probe, sentinels []net.IP) string {
	var b strings.Builder

	fmt.Fprintf(&b, "  rcode=%s flags=[%s] counts=an:%d,ns:%d,ar:%d\n",
		dns.RcodeToString[r.Rcode], flags(r), len(r.Answer), len(r.Ns), len(r.Extra))

	// Answer TTLs are printed exactly: blockTTL and customTTL are part of
	// the contract this capture guards. Authority and additional TTLs are
	// dropped — they count down against the cache (upstream 190d512), so
	// two runs against the same server would otherwise differ. That
	// countdown is measured deliberately by the ttlCountdown probe.
	fmt.Fprintf(&b, "  ANSWER:\n%s", section(r.Answer, p.volatile, false, sentinels))
	fmt.Fprintf(&b, "  AUTHORITY:\n%s", section(r.Ns, p.volatile, true, sentinels))
	fmt.Fprintf(&b, "  ADDITIONAL:\n%s", section(r.Extra, p.volatile, true, sentinels))

	return strings.TrimRight(b.String(), "\n")
}

// renderCountdown reports the shape of a repeated query's authority section
// and whether its TTL decreased, without printing either TTL — the absolute
// values depend on when the upstream answer happened to be cached.
func renderCountdown(first, second *dns.Msg) string {
	var b strings.Builder

	fmt.Fprintf(&b, "  rcode=%s flags=[%s] counts=an:%d,ns:%d,ar:%d\n",
		dns.RcodeToString[first.Rcode], flags(first), len(first.Answer), len(first.Ns), len(first.Extra))

	fmt.Fprintf(&b, "  AUTHORITY:\n%s", section(first.Ns, true, true, nil))
	fmt.Fprintf(&b, "  authority-ttl-counts-down=%s", countdownVerdict(first, second))

	return b.String()
}

func countdownVerdict(first, second *dns.Msg) string {
	switch {
	case len(first.Ns) == 0 || len(second.Ns) == 0:
		return "n/a (no authority section)"
	case len(first.Ns) != len(second.Ns):
		return "n/a (authority section changed shape between the two queries)"
	}

	for i := range first.Ns {
		if second.Ns[i].Header().Ttl < first.Ns[i].Header().Ttl {
			return "yes"
		}
	}

	return "no"
}

func flags(m *dns.Msg) string {
	var f []string

	for _, x := range []struct {
		on bool
		s  string
	}{
		{m.Response, "qr"},
		{m.Authoritative, "aa"},
		{m.Truncated, "tc"},
		{m.RecursionDesired, "rd"},
		{m.RecursionAvailable, "ra"},
		{m.AuthenticatedData, "ad"},
		{m.CheckingDisabled, "cd"},
	} {
		if x.on {
			f = append(f, x.s)
		}
	}

	return strings.Join(f, " ")
}

// section renders one message section, sorted so registration order cannot
// churn the capture. dropTTL is set for the authority and additional
// sections, whose TTLs count down against the cache.
func section(rrs []dns.RR, volatile, dropTTL bool, sentinels []net.IP) string {
	if len(rrs) == 0 {
		return "    (empty)\n"
	}

	out := make([]string, 0, len(rrs))

	for _, rr := range rrs {
		h := rr.Header()

		if opt, ok := rr.(*dns.OPT); ok {
			out = append(out, fmt.Sprintf("    OPT udpsize=%s do=%t options=%s",
				udpSize(opt, volatile), opt.Do(), optNames(opt)))

			continue
		}

		switch {
		case volatile:
			out = append(out, fmt.Sprintf("    %s %s %s",
				dns.TypeToString[h.Rrtype], h.Name, rdataClass(rr, sentinels)))
		case dropTTL:
			out = append(out, "    "+withoutTTL(rr))
		default:
			out = append(out, "    "+rr.String())
		}
	}

	sort.Strings(out)

	return strings.Join(out, "\n") + "\n"
}

// withoutTTL renders a record with its TTL replaced by a placeholder, for the
// sections where the TTL is a cache countdown rather than a value the fork
// controls.
func withoutTTL(rr dns.RR) string {
	c := dns.Copy(rr)
	c.Header().Ttl = 0

	return strings.Replace(c.String(), "\t0\t", "\tTTL\t", 1)
}

// rdataClass keeps a volatile record diffable without pinning live rdata: an
// address matching one of the instance's blocking sentinels is reported as
// such, because the whole point of the replay is to notice a name that
// changes between blocked and resolved. Anything else is just "live".
//
// Only address records can be classified this way. An nxDomain or refused
// blockType shows up in the rcode instead — but note that a zeroIP block of a
// query type with no zero value also answers a bare NXDOMAIN, which is not
// distinguishable here from an upstream NXDOMAIN.
func rdataClass(rr dns.RR, sentinels []net.IP) string {
	var ip net.IP

	switch v := rr.(type) {
	case *dns.A:
		ip = v.A
	case *dns.AAAA:
		ip = v.AAAA
	default:
		return "<live>"
	}

	if slices.ContainsFunc(sentinels, ip.Equal) {
		return "<blocked-sentinel>"
	}

	return "<live>"
}

// udpSize renders an OPT's advertised buffer size. On a volatile probe the
// value is whoever answered — our own 4096 on a cache hit, the upstream's
// 1232 on a miss — so it is elided rather than printed, or two runs against
// the same server differ on cache state alone. On a probe the fork answers
// itself the size is ours and worth pinning.
func udpSize(o *dns.OPT, volatile bool) string {
	if volatile {
		return "<responder>"
	}

	return strconv.Itoa(int(o.UDPSize()))
}

func optNames(o *dns.OPT) string {
	if len(o.Option) == 0 {
		return "none"
	}

	names := make([]string, 0, len(o.Option))
	for _, e := range o.Option {
		names = append(names, ednsOptionName(e.Option()))
	}

	sort.Strings(names)

	return strings.Join(names, ",")
}

func ednsOptionName(code uint16) string {
	switch code {
	case dns.EDNS0LLQ:
		return "LLQ"
	case dns.EDNS0NSID:
		return "NSID"
	case dns.EDNS0DAU:
		return "DAU"
	case dns.EDNS0DHU:
		return "DHU"
	case dns.EDNS0N3U:
		return "N3U"
	case dns.EDNS0SUBNET:
		return "SUBNET"
	case dns.EDNS0EXPIRE:
		return "EXPIRE"
	case dns.EDNS0COOKIE:
		return "COOKIE"
	case dns.EDNS0TCPKEEPALIVE:
		return "TCPKEEPALIVE"
	case dns.EDNS0PADDING:
		return "PADDING"
	case dns.EDNS0EDE:
		return "EDE"
	default:
		return fmt.Sprintf("OPT%d", code)
	}
}

// classifyErr reduces an exchange failure to a stable label. The raw error
// carries the ephemeral local port, which differs on every run and would make
// one failed capture undiffable against another.
func classifyErr(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout (no answer within " + exchangeTimeout.String() + ")"
	}

	switch {
	case errors.Is(err, net.ErrClosed):
		return "connection closed"
	case strings.Contains(err.Error(), "connection refused"):
		return "connection refused"
	case strings.Contains(err.Error(), "no route to host"):
		return "no route to host"
	default:
		return sanitize(err.Error())
	}
}

// sanitize replaces anything that parses as an address:port with a
// placeholder, so an unrecognised error still diffs cleanly.
func sanitize(msg string) string {
	fields := strings.Fields(msg)
	for i, f := range fields {
		host, _, err := net.SplitHostPort(strings.TrimSuffix(f, ":"))
		if err == nil && net.ParseIP(host) != nil {
			fields[i] = "<addr>"
		}
	}

	return strings.Join(fields, " ")
}
