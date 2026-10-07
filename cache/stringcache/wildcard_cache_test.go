package stringcache

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/0xERR0R/blocky/trie"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Compact wildcard cache", func() {
	It("matches the trie, including the reported parent, in either insertion order", func() {
		entries := []string{
			"*.Example.COM.", "*.child.example.com", "*.example.com",
			"*.child.blocked", "*.blocked", "*.xn--bcher-kva.example",
			"*.a..b.test", "*..single.", "*.",
		}
		for i := range 1000 {
			entries = append(entries, fmt.Sprintf("*.n%d.branch%d.test", i, i%23))
			if i%7 == 0 {
				entries = append(entries, fmt.Sprintf("*.branch%d.test", i%23))
			}
		}

		compareWildcardWithTrie(entries)
		for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
			entries[i], entries[j] = entries[j], entries[i]
		}
		compareWildcardWithTrie(entries)
	})

	It("matches repeated-dot queries against canonical rules", func() {
		factory := newWildcardCacheFactory()
		Expect(factory.addEntry("*.a.b.test")).To(BeTrue())
		cache := factory.create()

		for _, query := range []string{
			"x.a..b.test", "a...b..test.", ".a..b.test..",
			strings.Repeat("x.", 150) + "a..b.test",
		} {
			rule, ok := cache.findMatch(query)
			Expect(ok).To(BeTrue(), query)
			Expect(rule).To(Equal("*.a.b.test"), query)
		}
	})

	It("keeps misses allocation-free, including partial matches and empty labels", func() {
		factory := newWildcardCacheFactory()
		for _, entry := range []string{"*.a.shared.test", "*.b.other.test", "*.blocked"} {
			Expect(factory.addEntry(entry)).To(BeTrue())
		}
		cache := factory.create()

		for _, query := range []string{
			"unlisted.invalid", "c.shared.test", "shared.test", "TEST", "",
			"c..shared.test.", ".c.shared.test..", "a.shared.test.invalid",
		} {
			_, ok := cache.findMatch(query)
			Expect(ok).To(BeFalse(), query)
			Expect(testing.AllocsPerRun(100, func() { cache.findMatch(query) })).To(BeZero(), query)
		}
	})

	It("deduplicates storage while retaining the accepted-entry count", func() {
		factory := newWildcardCacheFactory()
		for _, entry := range []string{"*.EXAMPLE.test.", "*.example.test", "*.child.example.test"} {
			Expect(factory.addEntry(entry)).To(BeTrue())
		}
		cache := factory.create().(wildcardCache)
		Expect(cache.elementCount()).To(Equal(3))
		Expect(cache.tlds["test"].entries.elementCount()).To(Equal(2))
		Expect(factory.(*wildcardCacheFactory).tmp).To(BeEmpty())
		rule, ok := cache.findMatch("child.example.test")
		Expect(ok).To(BeTrue())
		Expect(rule).To(Equal("*.example.test"))
	})

	It("agrees with the trie on a supplied wildcard list", func() {
		path := os.Getenv("BLOCKY_WILDCARD_LIST")
		if path == "" {
			Skip("set BLOCKY_WILDCARD_LIST to a local wildcard list")
		}

		compareWildcardWithTrie(loadTestdata(path))
	})
})

func compareWildcardWithTrie(entries []string) {
	GinkgoHelper()
	factory := newWildcardCacheFactory()
	legacy := trie.NewTrie(trie.SplitTLD)
	queries := []string{"", ".", "..", "test", "com", "absent.invalid", "single", "blocked"}

	step := max(1, len(entries)/2500)
	for i, entry := range entries {
		if !strings.HasPrefix(entry, "*.") {
			continue
		}

		Expect(factory.addEntry(entry)).To(BeTrue())
		base := normalizeWildcard(entry)
		legacy.Insert(base)
		if i%step == 0 {
			queries = append(queries, base, "sub."+base, "a.b."+base, "not-"+base,
				base+".invalid", strings.ToUpper(base), base+".", "."+base,
				strings.ReplaceAll(base, ".", ".."))
		}
	}

	cache := factory.create()
	Expect(cache).NotTo(BeNil())
	for _, query := range queries {
		// Direct calls retain the trie's case-sensitive query contract. The
		// resolver lowercases DNS questions before calling the list cache.
		for _, name := range []string{query, util.ExtractDomainOnly(query)} {
			labels, want := legacy.HasParentOf(name)
			rule, got := cache.findMatch(name)
			Expect(got).To(Equal(want), name)
			if want {
				Expect(rule).To(Equal("*."+trie.JoinTLD(labels)), name)
			} else {
				Expect(rule).To(BeEmpty(), name)
			}
		}
	}
}
