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

// Golden-master tests: they parse list files with the production parser, build
// the grouped cache through the production chain and compare a canonical dump
// against a checked-in reference. The exact and wildcard caches only keep
// hashes, so they cannot be enumerated; their part of the dump is what the chain
// routed to them, recorded by a decorator around their real factories. The
// reference therefore pins the parser and the chain's routing; the caches
// themselves are checked by positive membership with the expected rule and by
// ElementCount. Negative behavior is covered by the oracle tests in
// wildcard_cache_test.go.
//
// Regenerate the references after an intentional behaviour change with:
//
//	go test ./cache/stringcache/ -run TestGolden -update-golden -count=1
var updateGolden = flag.Bool("update-golden", false, "regenerate golden-master references")

// edgeCaseParseErrors is the number of lines of edge_cases.txt that the production
// parser rejects (and lists.NewListCache skips with a warning): the "[Adblock Plus
// 2.0]" header, the 64-character label and the invalid IDNA or malformed wildcard
// lines, which the fixture includes on purpose. Rejected lines are not part of the
// dump, so their number is pinned here.
const edgeCaseParseErrors = 8

// TestGolden_EdgeCases pins the full cache contents for a small, curated fixture
// that exercises every supported list format and many edge cases. The reference
// is a full file so failures produce a readable diff.
func TestGolden_EdgeCases(t *testing.T) {
	fixture := filepath.Join("testdata", "golden", "edge_cases.txt")
	golden := filepath.Join("testdata", "golden", "edge_cases.golden")

	got, parseErrs := canonicalCacheDump(t, fixture)
	if parseErrs != edgeCaseParseErrors {
		t.Errorf("parser rejected %d lines of %s, want %d", parseErrs, fixture, edgeCaseParseErrors)
	}

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

	got, parseErrs := canonicalCacheDump(t, plain, wildcard)
	if parseErrs != 0 {
		t.Errorf("parser rejected %d lines of the oisd lists, want none", parseErrs)
	}

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
		if err := os.WriteFile(actual, []byte(got), 0o644); err != nil {
			t.Errorf("write actual dump: %v", err)
		}

		t.Fatalf("big-list cache dump changed:\n  got  %s\n  want %s\n(actual dump for inspection: %s)",
			gotHash, wantHash, actual)
	}
}

// canonicalCacheDump builds the grouped cache from the given list files using the
// same chain construction and build as lists.NewListCache, then returns a
// deterministic, order-independent dump of its contents and the number of parse
// errors the production parser reported.
//
// The dump lists regexes as compiled and, for exact and wildcard entries, what
// the chain routed to those caches (see recordingFactory); the chain is then
// asserted to find every one of those entries.
func canonicalCacheDump(t *testing.T, files ...string) (dump string, parseErrs int) {
	t.Helper()

	hosts, parseErrs := parseListFiles(t, files)

	const group = "default"

	// Same chain as lists.NewListCache: regex, then wildcard, then string.
	regexC := NewInMemoryGroupedRegexCache()
	wildC, wildRec := newRecordingGroupedCache(newWildcardCacheFactory)
	strC, strRec := newRecordingGroupedCache(newStringCacheFactory)

	chain := NewChainedGroupedCache(regexC, wildC, strC)

	// Single-threaded build => deterministic (equivalent to concurrency 1).
	factory := chain.Refresh(group)
	for _, h := range hosts {
		factory.AddEntry(h)
	}

	factory.Finish()

	strSet := make(map[string]struct{})
	for _, e := range strRec.accepted {
		strSet[strings.ToLower(e)] = struct{}{}
	}

	wildSet := make(map[string]struct{})
	for _, e := range wildRec.accepted {
		wildSet[normalizeWildcard(e)] = struct{}{}
	}

	var lines []string

	for e := range strSet {
		lines = append(lines, "string\t"+e)
	}

	// Regex cache: dump each compiled regex's source.
	regexCount := 0

	if rc, ok := (*regexC.caches.Load())[group]; ok && rc != nil {
		for _, re := range rc.(regexCache) {
			lines = append(lines, "regex\t"+re.String())
			regexCount++
		}
	}

	for w := range wildSet {
		lines = append(lines, "wildcard\t"+w)
	}

	assertChainMatchesEntries(t, chain, group, strSet, wildSet)

	if got, want := chain.ElementCount(group), regexCount+len(wildRec.accepted)+len(strSet); got != want {
		t.Errorf("ElementCount(%q) = %d, want %d (regex + accepted wildcards + unique strings)", group, got, want)
	}

	sort.Strings(lines)

	return strings.Join(lines, "\n") + "\n", parseErrs
}

// recordingFactory decorates a cacheFactory and records every entry it accepted
// into its cache, as opposed to entries it declined (so that the next cache of
// the chain gets them) or swallowed as invalid. Accepted entries are told apart
// by the factory's count() going up, which is how production counts them.
type recordingFactory struct {
	cacheFactory

	accepted []string
}

func (r *recordingFactory) addEntry(entry string) bool {
	before := r.count()

	ok := r.cacheFactory.addEntry(entry)
	if ok && r.count() > before {
		r.accepted = append(r.accepted, entry)
	}

	return ok
}

// newRecordingGroupedCache returns a grouped cache backed by the given real
// factory, and the recorder wrapped around the factory it creates on Refresh.
func newRecordingGroupedCache(inner stringCacheFactoryFn) (*InMemoryGroupedCache, *recordingFactory) {
	rec := &recordingFactory{}

	cache := newInMemoryGroupedCache(func() cacheFactory {
		rec.cacheFactory = inner()

		return rec
	})

	return cache, rec
}

// assertChainMatchesEntries checks that every exact and wildcard entry is found
// by the chain, reported under its own rule, or under the broader rule that
// shadows it: an exact entry wins over wildcards, and the shortest wildcard
// suffix wins over longer ones.
func assertChainMatchesEntries(t *testing.T, chain *ChainedGroupedCache, group string,
	strSet, wildSet map[string]struct{},
) {
	t.Helper()

	check := func(entry, wantRule string) {
		t.Helper()

		if got := chain.Contains(entry, []string{group})[group]; got != wantRule {
			t.Errorf("Contains(%q) matched rule %q, want %q", entry, got, wantRule)
		}
	}

	for e := range strSet {
		check(e, e)
	}

	// The wildcard cache ignores empty labels, so compare against collapsed rules.
	rules := make(map[string]struct{}, len(wildSet))
	for w := range wildSet {
		rules[collapseDots(w)] = struct{}{}
	}

	for w := range wildSet {
		collapsed := collapseDots(w)
		if collapsed == "" {
			continue // "*." alone matches nothing
		}

		if _, exact := strSet[w]; exact {
			check(w, w)

			continue
		}

		want := collapsed

		for suffix := collapsed; suffix != ""; {
			if _, ok := rules[suffix]; ok {
				want = suffix
			}

			_, suffix, _ = strings.Cut(suffix, ".")
		}

		check(w, "*."+want)
	}
}

// parseListFiles parses each file with the production parser and applies the same
// IP normalization as lists.parseFile, yielding the host stream that reaches the cache
// and the number of lines the parser rejected (and production skips with a warning).
func parseListFiles(t *testing.T, files []string) (hosts []string, parseErrs int) {
	t.Helper()

	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}

		p := parsers.AllowErrors(parsers.Hosts(f), parsers.NoErrorLimit)
		p.OnErr(func(error) { parseErrs++ })

		err = parsers.ForEach[*parsers.HostsIterator](context.Background(), p,
			func(entry *parsers.HostsIterator) error {
				return entry.ForEach(func(host string) error {
					if parsers.MightBeIP(host) {
						if ip := net.ParseIP(host); ip != nil {
							host = ip.String()
						}
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

	return hosts, parseErrs
}

// firstDiff returns a short description of the first line that differs between
// want and got, to make golden mismatches readable.
func firstDiff(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")

	n := min(len(wantLines), len(gotLines))

	for i := range n {
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
