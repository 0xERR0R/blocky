package resolver

import (
	"fmt"
	"testing"

	"github.com/0xERR0R/blocky/config"

	"github.com/miekg/dns"
)

// benchClientGroupsBlock builds a clientGroupsBlock mapping of the shape a busy
// deployment accumulates: many IP/CIDR/FQDN identifiers plus a handful of literal
// client names and a couple of glob name patterns. It stresses the client-name
// resolution path that Tier 2d targets, where filepath.Match was run against every
// identifier in the map for each client name.
func benchClientGroupsBlock() map[string][]string {
	m := make(map[string][]string)

	for i := range 200 {
		m[fmt.Sprintf("10.0.%d.%d", i/256, i%256)] = []string{"gr-ip"}
	}

	for i := range 20 {
		m[fmt.Sprintf("172.16.%d.0/24", i)] = []string{"gr-cidr"}
	}

	for i := range 20 {
		m[fmt.Sprintf("host%d.lan.example.com", i)] = []string{"gr-fqdn"}
	}

	for i := range 10 {
		m[fmt.Sprintf("laptop-%d", i)] = []string{"gr-name"}
	}

	m["wildcard[0-9]*"] = []string{"gr-glob"}
	m["kiosk-*"] = []string{"gr-glob"}
	m["default"] = []string{"gr-default"}

	return m
}

func newBenchBlockingResolver() *BlockingResolver {
	cfg := config.Blocking{ClientGroupsBlock: benchClientGroupsBlock()}

	return &BlockingResolver{
		clientGroups: newClientGroupsIndex(cfg),
		status:       &status{enabled: true},
	}
}

// BenchmarkBlockingGroupsToCheckLiteralName resolves the groups for a request whose
// client name is a literal (the common case). Today every identifier in the map is
// run through filepath.Match; an exact map lookup plus a tiny glob scan should be
// far cheaper.
func BenchmarkBlockingGroupsToCheckLiteralName(b *testing.B) {
	r := newBenchBlockingResolver()
	req := newRequestWithClient("example.com.", dns.Type(dns.TypeA), "10.0.0.5", "laptop-7")

	b.ReportAllocs()

	for b.Loop() {
		if got := r.groupsToCheckForClient(req); len(got) == 0 {
			b.Fatal("expected at least one group")
		}
	}
}

// BenchmarkBlockingGroupsToCheckGlobName resolves the groups for a request whose
// client name only matches a glob pattern, keeping filepath.Match on the hot path.
func BenchmarkBlockingGroupsToCheckGlobName(b *testing.B) {
	r := newBenchBlockingResolver()
	req := newRequestWithClient("example.com.", dns.Type(dns.TypeA), "10.0.0.5", "kiosk-lobby")

	b.ReportAllocs()

	for b.Loop() {
		if got := r.groupsToCheckForClient(req); len(got) == 0 {
			b.Fatal("expected at least one group")
		}
	}
}
