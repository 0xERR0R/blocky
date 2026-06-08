package stringcache

import (
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

			It("counts every insertion but stores only unique entries", func() {
				Expect(factory.count()).Should(Equal(5))
				Expect(cache.elementCount()).Should(Equal(3))
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
