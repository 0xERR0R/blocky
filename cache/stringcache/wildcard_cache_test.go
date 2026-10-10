package stringcache

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hashed wildcard cache", func() {
	build := func(entries ...string) stringCache {
		GinkgoHelper()

		factory := newWildcardCacheFactory()
		for _, entry := range entries {
			Expect(factory.addEntry(entry)).To(BeTrue(), entry)
		}

		return factory.create()
	}

	It("agrees with a naive oracle, including the reported parent, in either insertion order", func() {
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

		suffixes := make([]string, len(entries))
		for i, entry := range entries {
			suffixes[i] = strings.TrimPrefix(entry, "*.")
		}

		queries := slices.Grow([]string{"", ".", "..", "test", "com", "absent.invalid", "single", "blocked"},
			len(entries)*len(queriesAround("")))
		for _, entry := range entries {
			queries = append(queries, queriesAround(normalizeWildcard(entry))...)
		}

		for range 2 {
			cache := build(entries...)

			for _, query := range queries {
				wantRule, wantOK := naiveWildcardMatch(suffixes, query)
				rule, ok := cache.findMatch(query)
				Expect(ok).To(Equal(wantOK), query)
				Expect(rule).To(Equal(wantRule), query)
			}

			for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
				entries[i], entries[j] = entries[j], entries[i]
				suffixes[i], suffixes[j] = suffixes[j], suffixes[i]
			}
		}
	})

	DescribeTable("matches",
		func(entries []string, query, wantRule string) {
			rule, ok := build(entries...).findMatch(query)

			Expect(ok).To(Equal(wantRule != ""), query)
			Expect(rule).To(Equal(wantRule), query)
		},
		Entry("a bare TLD rule matches the TLD itself", []string{"*.com"}, "com", "*.com"),
		Entry("a bare TLD rule matches everything below", []string{"*.com"}, "a.b.com", "*.com"),
		Entry("a bare TLD rule does not match other TLDs", []string{"*.com"}, "example.net", ""),
		Entry("a rule matches the domain itself", []string{"*.example.com"}, "example.com", "*.example.com"),
		Entry("a rule does not match its TLD", []string{"*.example.com"}, "com", ""),
		Entry("the broadest parent wins", []string{"*.a.com", "*.com"}, "x.a.com", "*.com"),
		Entry("a shadowed child does not change the rule", []string{"*.child.example.com", "*.example.com"},
			"child.example.com", "*.example.com"),
		Entry("a child rule matches without its parent", []string{"*.child.example.com"},
			"child.example.com", "*.child.example.com"),
		Entry("a child rule does not match its parent", []string{"*.child.example.com"}, "example.com", ""),
		Entry("repeated dots in the rule are collapsed", []string{"*.a..b.test"}, "a.b.test", "*.a.b.test"),
		Entry("repeated dots in the query are skipped", []string{"*.a.b.test"}, "x.a..b.test", "*.a.b.test"),
		Entry("a lone '*.' matches nothing", []string{"*."}, "example.com", ""),
		Entry("a single label rule matches", []string{"*.blocked"}, "sub.blocked", "*.blocked"),
		Entry("empty query", []string{"*.com"}, "", ""),
		Entry("dot query", []string{"*.com"}, ".", ""),
		Entry("double dot query", []string{"*.com"}, "..", ""),
		Entry("leading dot", []string{"*.example.com"}, ".www.example.com", "*.example.com"),
		Entry("trailing dot", []string{"*.example.com"}, "www.example.com.", "*.example.com"),
		Entry("trailing dots on the matched suffix", []string{"*.example.com"}, "example.com..", "*.example.com"),
		Entry("empty label inside the query", []string{"*.example.com"}, "a..example.com", "*.example.com"),
		Entry("long query", []string{"*.example.com"}, strings.Repeat("a.", 200)+"example.com", "*.example.com"),
		Entry("long rule", []string{"*." + strings.Repeat("a.", 200) + "com"},
			"x."+strings.Repeat("a.", 200)+"com", "*."+strings.Repeat("a.", 200)+"com"),
		Entry("uppercase query", []string{"*.example.com"}, "WWW.EXAMPLE.COM", "*.example.com"),
		Entry("uppercase rule", []string{"*.EXAMPLE.Com"}, "www.example.com", "*.example.com"),
		Entry("unicode rule and query", []string{"*.bücher.example"}, "WWW.BÜCHER.EXAMPLE", "*.bücher.example"),
		Entry("unicode query below an ASCII rule", []string{"*.example"}, "BÜCHER.EXAMPLE", "*.example"),
		Entry("suffix without a label boundary", []string{"*.example.com"}, "an-example.com", ""),
		Entry("prefix of a rule", []string{"*.example.com"}, "example.coma", ""),
	)

	It("counts accepted entries including duplicates, and keeps a cache for entries that match nothing", func() {
		factory := newWildcardCacheFactory()
		for _, entry := range []string{"*.EXAMPLE.test.", "*.example.test", "*.child.example.test"} {
			Expect(factory.addEntry(entry)).To(BeTrue())
		}

		Expect(factory.count()).To(Equal(3))

		cache := factory.create()
		Expect(cache.elementCount()).To(Equal(3))

		rule, ok := cache.findMatch("child.example.test")
		Expect(ok).To(BeTrue())
		Expect(rule).To(Equal("*.example.test"))

		onlyEmpty := build("*.")
		Expect(onlyEmpty).NotTo(BeNil())
		Expect(onlyEmpty.elementCount()).To(Equal(1))
	})

	It("creates the same cache again when asked twice, also for entries that match nothing", func() {
		factory := newWildcardCacheFactory()
		for _, entry := range []string{"*.b.test", "*.", "*.a.test"} {
			Expect(factory.addEntry(entry)).To(BeTrue(), entry)
		}

		first := factory.create()
		second := factory.create()

		Expect(second).NotTo(BeNil())
		Expect(second.elementCount()).To(Equal(first.elementCount()))

		rule, ok := second.findMatch("www.A.test")
		Expect(ok).To(BeTrue())
		Expect(rule).To(Equal("*.a.test"))
	})

	It("keeps misses allocation-free, including partial matches, uppercase and empty labels", func() {
		cache := build("*.a.shared.test", "*.b.other.test", "*.blocked")

		for _, query := range []string{
			"unlisted.invalid", "c.shared.test", "shared.test", "TEST", "",
			"c..shared.test.", ".c.shared.test..", "a.shared.test.invalid",
		} {
			_, ok := cache.findMatch(query)
			Expect(ok).To(BeFalse(), query)
			Expect(testing.AllocsPerRun(100, func() { cache.findMatch(query) })).To(BeZero(), query)
		}
	})
})

// cleanLabels splits a domain into its lowercase, non-empty labels.
func cleanLabels(domain string) []string {
	return strings.FieldsFunc(strings.ToLower(domain), func(c rune) bool { return c == '.' })
}

// naiveWildcardMatch is the specification of the wildcard cache: the shortest
// suffix of the query's labels that equals a rule's labels wins.
func naiveWildcardMatch(entries []string, query string) (string, bool) {
	rules := make(map[string]struct{})

	for _, entry := range entries {
		if clean := strings.Join(cleanLabels(entry), "."); clean != "" {
			rules[clean] = struct{}{}
		}
	}

	labels := cleanLabels(query)
	for i := range slices.Backward(labels) {
		suffix := strings.Join(labels[i:], ".")
		if _, ok := rules[suffix]; ok {
			return "*." + suffix, true
		}
	}

	return "", false
}

func FuzzWildcardCacheMatchesNaiveOracle(f *testing.F) {
	f.Add("example.com", "child.example.com", "www.EXAMPLE.com.")
	f.Add("com", "a.b.com", "x.a..b.com")
	f.Add("a..b", "..", "..a.b..")
	f.Add("", ".", "")
	f.Add("Bücher.example", "example", "BÜCHER.EXAMPLE")
	f.Add(strings.Repeat("a.", 200)+"com", "com", "x."+strings.Repeat("a.", 200)+"com")

	f.Fuzz(func(t *testing.T, ruleA, ruleB, query string) {
		factory := newWildcardCacheFactory()
		entries := []string{ruleA, ruleB}

		var accepted []string

		for _, entry := range entries {
			if strings.Contains(entry, "*") {
				continue // validation of '*' is covered by the cache specs
			}

			if !factory.addEntry("*." + entry) {
				t.Fatalf("addEntry(%q) = false, want true", "*."+entry)
			}

			accepted = append(accepted, entry)
		}

		cache := factory.create()
		if cache == nil {
			return
		}

		gotRule, gotOK := cache.findMatch(query)
		wantRule, wantOK := naiveWildcardMatch(accepted, query)

		if gotOK != wantOK || gotRule != wantRule {
			t.Fatalf("rules %q, query %q: got (%q, %v), want (%q, %v)",
				accepted, query, gotRule, gotOK, wantRule, wantOK)
		}
	})
}

// queriesAround returns queries that hit, nearly hit and miss the rule for base.
func queriesAround(base string) []string {
	return []string{
		base, "sub." + base, "a.b." + base, "not-" + base, base + ".invalid",
		strings.ToUpper(base), base + ".", "." + base, strings.ReplaceAll(base, ".", ".."),
	}
}
