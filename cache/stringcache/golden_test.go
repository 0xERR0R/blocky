package stringcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/0xERR0R/blocky/lists/parsers"
)

// Golden-master tests: they build the grouped cache from list files through the
// production parse -> classify -> build code paths and compare a canonical dump
// of its contents against a checked-in reference. Any change to parsing or cache
// construction that alters which entries end up in the cache (or how they are
// normalized) changes the dump and fails these tests.
//
// Regenerate the references after an intentional behaviour change with:
//
//	go test ./cache/stringcache/ -run TestGolden -update-golden -count=1
var updateGolden = flag.Bool("update-golden", false, "regenerate golden-master references")

// TestGolden_EdgeCases pins the full cache contents for a small, curated fixture
// that exercises every supported list format and many edge cases. The reference
// is a full file so failures produce a readable diff.
func TestGolden_EdgeCases(t *testing.T) {
	fixture := filepath.Join("testdata", "golden", "edge_cases.txt")
	golden := filepath.Join("testdata", "golden", "edge_cases.golden")

	got := canonicalCacheDump(t, fixture)

	if *updateGolden {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}

		t.Logf("updated %s", golden)

		return
	}

	wantBytes, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update-golden to create): %v", err)
	}

	if want := string(wantBytes); got != want {
		t.Fatalf("cache dump differs from %s:\n%s", golden, firstDiff(want, got))
	}
}

// TestGolden_BigLists pins the cache contents for the real oisd lists (~890k
// entries) via a hash, so it stays cheap to store while still detecting any
// behaviour change across the full, real-world input.
func TestGolden_BigLists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping big-list golden in -short mode")
	}

	plain := filepath.Join("..", "..", "helpertest", "data", "oisd-big-plain.txt")
	wildcard := filepath.Join("..", "..", "helpertest", "data", "oisd-big-wildcard.txt")

	got := canonicalCacheDump(t, plain, wildcard)

	sum := sha256.Sum256([]byte(got))
	gotHash := hex.EncodeToString(sum[:])

	// sha256 of the canonical dump of oisd-big-plain + oisd-big-wildcard.
	// Regenerate with -update-golden after an intentional behaviour change.
	const wantHash = "cb5c01e7d84b991d648c59fae6b44100c759087fafcf1a447d104e3087dbf940"

	if *updateGolden {
		t.Logf("big-list dump sha256 = %s", gotHash)

		return
	}

	if gotHash != wantHash {
		actual := filepath.Join("testdata", "golden", "big_lists.actual")
		_ = os.WriteFile(actual, []byte(got), 0o644)

		t.Fatalf("big-list cache dump changed:\n  got  %s\n  want %s\n(wrote actual dump to %s for inspection)",
			gotHash, wantHash, actual)
	}
}

// canonicalCacheDump builds the grouped cache from the given list files using the
// same chain construction, classification and build as lists.NewListCache, then
// returns a deterministic, order-independent dump of its contents.
func canonicalCacheDump(t *testing.T, files ...string) string {
	t.Helper()

	hosts := parseListFiles(t, files)

	const group = "default"

	// Same chain as lists.NewListCache: regex, then wildcard, then string.
	regexC := NewInMemoryGroupedRegexCache()
	wildC := NewInMemoryGroupedWildcardCache()
	strC := NewInMemoryGroupedStringCache()

	chain := NewChainedGroupedCache(regexC, wildC, strC)

	// Single-threaded build => deterministic (equivalent to concurrency 1).
	factory := chain.Refresh(group)
	for _, h := range hosts {
		factory.AddEntry(h)
	}

	factory.Finish()

	var lines []string

	// String cache: enumerate the real built stringMap.
	if sc, ok := strC.caches[group]; ok && sc != nil {
		for _, e := range enumerateStringMap(sc.(stringMap)) {
			lines = append(lines, "string\t"+e)
		}
	}

	// Regex cache: dump each compiled regex's source.
	if rc, ok := regexC.caches[group]; ok && rc != nil {
		for _, re := range rc.(regexCache) {
			lines = append(lines, "regex\t"+re.String())
		}
	}

	// Wildcard cache: the trie is not enumerable, so reconstruct the normalized
	// keys it was fed, mirroring production classification (regex wins over
	// wildcard) and the wildcard factory's validity check.
	wildSet := make(map[string]struct{})

	for _, h := range hosts {
		if strings.HasPrefix(h, "/") && strings.HasSuffix(h, "/") {
			continue // regex
		}

		if !strings.HasPrefix(h, "*.") || strings.Count(h, "*") != 1 {
			continue // not a (valid) wildcard
		}

		wildSet[normalizeWildcard(h)] = struct{}{}
	}

	for w := range wildSet {
		lines = append(lines, "wildcard\t"+w)
	}

	sort.Strings(lines)

	return strings.Join(lines, "\n") + "\n"
}

// enumerateStringMap returns every entry stored in a stringMap. Each bucket is a
// concatenation of equal-length entries, so it is split into fixed-width chunks.
func enumerateStringMap(m stringMap) []string {
	var out []string

	for k, v := range m {
		if k <= 0 {
			continue
		}

		for i := 0; i+k <= len(v); i += k {
			out = append(out, v[i:i+k])
		}
	}

	return out
}

// parseListFiles parses each file with the production parser and applies the same
// IP normalization as lists.parseFile, yielding the host stream that reaches the cache.
func parseListFiles(t *testing.T, files []string) []string {
	t.Helper()

	var hosts []string

	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}

		p := parsers.AllowErrors(parsers.Hosts(f), parsers.NoErrorLimit)
		p.OnErr(func(error) {})

		err = parsers.ForEach[*parsers.HostsIterator](context.Background(), p,
			func(entry *parsers.HostsIterator) error {
				return entry.ForEach(func(host string) error {
					if ip := net.ParseIP(host); ip != nil {
						host = ip.String()
					}

					hosts = append(hosts, host)

					return nil
				})
			})

		f.Close()

		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
	}

	return hosts
}

// firstDiff returns a short description of the first line that differs between
// want and got, to make golden mismatches readable.
func firstDiff(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")

	n := len(wantLines)
	if len(gotLines) < n {
		n = len(gotLines)
	}

	for i := 0; i < n; i++ {
		if wantLines[i] != gotLines[i] {
			return firstDiffMsg(i, wantLines[i], gotLines[i], len(wantLines), len(gotLines))
		}
	}

	return firstDiffMsg(n, "", "", len(wantLines), len(gotLines))
}

func firstDiffMsg(line int, want, got string, wantN, gotN int) string {
	return fmt.Sprintf("  first difference at line %d (want %d lines, got %d):\n  - want: %s\n  + got:  %s",
		line+1, wantN, gotN, want, got)
}
