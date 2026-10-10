package stringcache

import (
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Caches", func() {
	var (
		cache   stringCache
		factory cacheFactory
	)

	Describe("String StringCache", func() {
		It("should not return a cache when empty", func() {
			Expect(newStringCacheFactory().create()).Should(BeNil())
		})

		It("should recognise the empty string", func() {
			factory := newStringCacheFactory()

			Expect(factory.addEntry("")).Should(BeTrue())

			Expect(factory.count()).Should(BeNumerically("==", 0))
			Expect(factory.create()).Should(BeNil())
		})

		When("string StringCache was created", func() {
			BeforeEach(func() {
				factory = newStringCacheFactory()
				Expect(factory.addEntry("google.com")).Should(BeTrue())
				Expect(factory.addEntry("apple.com")).Should(BeTrue())
				Expect(factory.addEntry("")).Should(BeTrue()) // invalid, but handled
				Expect(factory.addEntry("google.com")).Should(BeTrue())
				Expect(factory.addEntry("APPLe.com")).Should(BeTrue())

				cache = factory.create()
			})

			It("should match if StringCache contains exact string", func() {
				rule, ok := cache.findMatch("apple.com")
				Expect(ok).Should(BeTrue())
				Expect(rule).Should(Equal("apple.com"))

				rule, ok = cache.findMatch("google.com")
				Expect(ok).Should(BeTrue())
				Expect(rule).Should(Equal("google.com"))

				_, ok = cache.findMatch("www.google.com")
				Expect(ok).Should(BeFalse())
				_, ok = cache.findMatch("")
				Expect(ok).Should(BeFalse())
			})

			It("should match case-insensitive and return the normalized rule", func() {
				rule, ok := cache.findMatch("aPPle.com")
				Expect(ok).Should(BeTrue())
				Expect(rule).Should(Equal("apple.com"))

				rule, ok = cache.findMatch("google.COM")
				Expect(ok).Should(BeTrue())
				Expect(rule).Should(Equal("google.com"))

				_, ok = cache.findMatch("www.google.com")
				Expect(ok).Should(BeFalse())
				_, ok = cache.findMatch("")
				Expect(ok).Should(BeFalse())
			})

			It("should return correct element count", func() {
				Expect(factory.count()).Should(Equal(4))
				Expect(cache.elementCount()).Should(Equal(2))
			})
		})

		DescribeTable("exact matching",
			func(entries []string, query, wantRule string) {
				factory := newStringCacheFactory()
				for _, entry := range entries {
					Expect(factory.addEntry(entry)).To(BeTrue(), entry)
				}

				rule, ok := factory.create().findMatch(query)

				Expect(ok).To(Equal(wantRule != ""), query)
				Expect(rule).To(Equal(wantRule), query)
			},
			Entry("empty query", []string{"a.com"}, "", ""),
			Entry("trailing dot query", []string{"example.com"}, "example.com.", ""),
			Entry("trailing dot entry", []string{"example.com."}, "example.com", ""),
			Entry("prefix of an entry", []string{"example.com"}, "example.co", ""),
			Entry("suffix of an entry", []string{"example.com"}, "xample.com", ""),
			Entry("parent domain", []string{"www.example.com"}, "example.com", ""),
			Entry("long entry", []string{strings.Repeat("a", 300) + ".com"},
				strings.Repeat("a", 300)+".com", strings.Repeat("a", 300)+".com"),
			Entry("unicode entry and query in different case", []string{"Bücher.example"},
				"BÜCHER.EXAMPLE", "bücher.example"),
			Entry("IPv4", []string{"192.168.1.1"}, "192.168.1.1", "192.168.1.1"),
			Entry("IPv6", []string{"2001:db8::1"}, "2001:DB8::1", "2001:db8::1"),
		)

		It("keeps misses allocation-free, including uppercase and empty queries", func() {
			factory := newStringCacheFactory()
			Expect(factory.addEntry("listed.example")).Should(BeTrue())

			cache := factory.create()

			for _, query := range []string{"UNLISTED.EXAMPLE", "Listed.Example.Invalid", ""} {
				_, ok := cache.findMatch(query)
				Expect(ok).To(BeFalse(), query)
				Expect(testing.AllocsPerRun(100, func() { cache.findMatch(query) })).To(BeZero(), query)
			}
		})

		It("creates the same cache again when asked twice", func() {
			factory := newStringCacheFactory()
			Expect(factory.addEntry("b.com")).Should(BeTrue())
			Expect(factory.addEntry("a.com")).Should(BeTrue())

			first := factory.create()
			second := factory.create()

			Expect(second).NotTo(BeNil())
			Expect(second.elementCount()).Should(Equal(first.elementCount()))

			rule, ok := second.findMatch("A.com")
			Expect(ok).Should(BeTrue())
			Expect(rule).Should(Equal("a.com"))
		})

		It("keeps an earlier cache unchanged when entries are added after create", func() {
			factory := newStringCacheFactory()
			Expect(factory.addEntry("a.com")).Should(BeTrue())

			before := factory.create()

			Expect(factory.addEntry("b.com")).Should(BeTrue())

			after := factory.create()

			Expect(before.elementCount()).Should(Equal(1))
			_, ok := before.findMatch("b.com")
			Expect(ok).Should(BeFalse())

			Expect(after.elementCount()).Should(Equal(2))
			_, ok = after.findMatch("b.com")
			Expect(ok).Should(BeTrue())
		})

		When("entries are added unsorted with duplicates", func() {
			var entries []string

			BeforeEach(func() {
				factory = newStringCacheFactory()

				// reverse-sorted, all the same length (a single length bucket),
				// plus an exact and a case-insensitive duplicate
				entries = []string{"zzz.example", "mmm.example", "aaa.example"}
				for _, e := range entries {
					Expect(factory.addEntry(e)).Should(BeTrue())
				}
				Expect(factory.addEntry("AAA.example")).Should(BeTrue()) // case-insensitive duplicate
				Expect(factory.addEntry("mmm.example")).Should(BeTrue()) // exact duplicate

				cache = factory.create()
			})

			It("finds every entry regardless of insertion order", func() {
				for _, e := range entries {
					rule, ok := cache.findMatch(e)
					Expect(ok).Should(BeTrue(), e)
					Expect(rule).Should(Equal(e), e)
				}
			})
		})
	})

	Describe("Regex StringCache", func() {
		It("should not return a cache when empty", func() {
			Expect(newRegexCacheFactory().create()).Should(BeNil())
		})

		It("should recognise invalid regexes", func() {
			factory := newRegexCacheFactory()

			Expect(factory.addEntry("/*/")).Should(BeTrue())
			Expect(factory.addEntry("/?/")).Should(BeTrue())
			Expect(factory.addEntry("/+/")).Should(BeTrue())
			Expect(factory.addEntry("/[/")).Should(BeTrue())

			Expect(factory.count()).Should(BeNumerically("==", 0))
			Expect(factory.create()).Should(BeNil())
		})

		It("should not treat a lone slash as a regex and must not panic", func() {
			factory := newRegexCacheFactory()

			// "/" is both prefix and suffix, so without a length guard it slips
			// past the delimiter check and panics on entry[1:len-1] ("/"[1:0]).
			Expect(func() { factory.addEntry("/") }).ShouldNot(Panic())
			Expect(factory.addEntry("/")).Should(BeFalse())
			Expect(factory.count()).Should(BeNumerically("==", 0))
		})

		When("regex StringCache was created", func() {
			BeforeEach(func() {
				factory = newRegexCacheFactory()
				Expect(factory.addEntry("/.*google.com/")).Should(BeTrue())
				Expect(factory.addEntry("/^apple\\.(de|com)$/")).Should(BeTrue())
				Expect(factory.addEntry("/amazon/")).Should(BeTrue())
				Expect(factory.addEntry("/(wrongRegex/")).Should(BeTrue()) // recognized as regex but ignored because invalid
				Expect(factory.addEntry("plaintext")).Should(BeFalse())

				cache = factory.create()
			})

			It("should match if one regex in StringCache matches string and return the pattern", func() {
				rule, ok := cache.findMatch("google.com")
				Expect(ok).Should(BeTrue())
				Expect(rule).Should(Equal("/.*google.com/"))

				_, ok = cache.findMatch("google.coma")
				Expect(ok).Should(BeTrue())
				_, ok = cache.findMatch("agoogle.com")
				Expect(ok).Should(BeTrue())
				_, ok = cache.findMatch("www.google.com")
				Expect(ok).Should(BeTrue())

				rule, ok = cache.findMatch("apple.com")
				Expect(ok).Should(BeTrue())
				Expect(rule).Should(Equal("/^apple\\.(de|com)$/"))

				_, ok = cache.findMatch("apple.de")
				Expect(ok).Should(BeTrue())
				_, ok = cache.findMatch("apple.it")
				Expect(ok).Should(BeFalse())
				_, ok = cache.findMatch("www.apple.com")
				Expect(ok).Should(BeFalse())
				_, ok = cache.findMatch("applecom")
				Expect(ok).Should(BeFalse())

				rule, ok = cache.findMatch("www.amazon.com")
				Expect(ok).Should(BeTrue())
				Expect(rule).Should(Equal("/amazon/"))

				_, ok = cache.findMatch("amazon.com")
				Expect(ok).Should(BeTrue())
				_, ok = cache.findMatch("myamazon.com")
				Expect(ok).Should(BeTrue())
			})

			It("should return correct element count", func() {
				Expect(factory.count()).Should(Equal(3))
				Expect(cache.elementCount()).Should(Equal(3))
			})
		})
	})

	Describe("Wildcard StringCache", func() {
		It("should not return a cache when empty", func() {
			Expect(newWildcardCacheFactory().create()).Should(BeNil())
		})

		It("should recognise invalid wildcards", func() {
			factory := newWildcardCacheFactory()

			Expect(factory.addEntry("example.*.com")).Should(BeTrue())
			Expect(factory.addEntry("example.*")).Should(BeTrue())
			Expect(factory.addEntry("sub.*.example.com")).Should(BeTrue())
			Expect(factory.addEntry("*.example.*")).Should(BeTrue())

			Expect(factory.count()).Should(BeNumerically("==", 0))
			Expect(factory.create()).Should(BeNil())
		})

		When("cache was created", func() {
			BeforeEach(func() {
				factory = newWildcardCacheFactory()

				Expect(factory.addEntry("*.example.com")).Should(BeTrue())
				Expect(factory.addEntry("*.example.org")).Should(BeTrue())
				Expect(factory.addEntry("*.blocked")).Should(BeTrue())
				Expect(factory.addEntry("*.sub.blocked")).Should(BeTrue()) // already handled by above

				cache = factory.create()
			})

			It("should match and return the wildcard rule including the '*.' prefix", func() {
				// first entry
				rule, ok := cache.findMatch("example.com")
				Expect(ok).Should(BeTrue())
				Expect(rule).Should(Equal("*.example.com"))

				rule, ok = cache.findMatch("www.example.com")
				Expect(ok).Should(BeTrue())
				Expect(rule).Should(Equal("*.example.com"))

				// look alikes
				_, ok = cache.findMatch("com")
				Expect(ok).Should(BeFalse())
				_, ok = cache.findMatch("example.coma")
				Expect(ok).Should(BeFalse())
				_, ok = cache.findMatch("an-example.com")
				Expect(ok).Should(BeFalse())
				_, ok = cache.findMatch("examplecom")
				Expect(ok).Should(BeFalse())

				// other entry
				rule, ok = cache.findMatch("example.org")
				Expect(ok).Should(BeTrue())
				Expect(rule).Should(Equal("*.example.org"))

				_, ok = cache.findMatch("www.example.org")
				Expect(ok).Should(BeTrue())

				// unrelated
				_, ok = cache.findMatch("example.net")
				Expect(ok).Should(BeFalse())
				_, ok = cache.findMatch("www.example.net")
				Expect(ok).Should(BeFalse())

				// third entry (single label)
				rule, ok = cache.findMatch("blocked")
				Expect(ok).Should(BeTrue())
				Expect(rule).Should(Equal("*.blocked"))

				_, ok = cache.findMatch("sub.blocked")
				Expect(ok).Should(BeTrue())
				_, ok = cache.findMatch("sub.sub.blocked")
				Expect(ok).Should(BeTrue())
				_, ok = cache.findMatch("example.blocked")
				Expect(ok).Should(BeTrue())
			})

			It("should return correct element count", func() {
				Expect(factory.count()).Should(Equal(4))
				Expect(cache.elementCount()).Should(Equal(4))
			})
		})
	})
})

func FuzzStringCacheMatchesMapOracle(f *testing.F) {
	f.Add("example.com", "Other.COM", "EXAMPLE.com")
	f.Add("", "a", "")
	f.Add("Bücher.example", "İSTANBUL.example", "BÜCHER.EXAMPLE")
	f.Add("*.example.com", "/regex/", "/REGEX/")
	f.Add("example.com.", "a..b", "A..B")
	f.Add("\xff", "A\xffB", "a\xffb")

	f.Fuzz(func(t *testing.T, entryA, entryB, query string) {
		factory := newStringCacheFactory()
		oracle := make(map[string]struct{})

		for _, entry := range []string{entryA, entryB} {
			if !factory.addEntry(entry) {
				t.Fatalf("addEntry(%q) = false, want true", entry)
			}

			if entry != "" {
				oracle[strings.ToLower(entry)] = struct{}{}
			}
		}

		cache := factory.create()
		if cache == nil {
			return
		}

		gotRule, gotOK := cache.findMatch(query)

		wantRule := strings.ToLower(query)
		_, wantOK := oracle[wantRule]

		if query == "" {
			wantOK = false
		}

		if !wantOK {
			wantRule = ""
		}

		if gotOK != wantOK || gotRule != wantRule {
			t.Fatalf("entries %q, query %q: got (%q, %v), want (%q, %v)",
				[]string{entryA, entryB}, query, gotRule, gotOK, wantRule, wantOK)
		}

		if got := cache.elementCount(); got != len(oracle) {
			t.Fatalf("entries %q: elementCount() = %d, want %d", []string{entryA, entryB}, got, len(oracle))
		}
	})
}
