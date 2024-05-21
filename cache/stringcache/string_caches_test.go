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
				contains, _ := cache.contains("apple.com")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("google.com")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("www.google.com")
				Expect(contains).Should(BeFalse())
				contains, _ = cache.contains("www.google.com")
				Expect(cache.contains("")).Should(BeFalse())
			})

			It("should match case-insensitive", func() {
				contains, _ := cache.contains("aPPle.com")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("google.COM")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("www.google.com")
				Expect(contains).Should(BeFalse())
				contains, _ = cache.contains("")
				Expect(contains).Should(BeFalse())
			})

			It("should return correct element count", func() {
				Expect(factory.count()).Should(Equal(4))
				Expect(cache.elementCount()).Should(Equal(2))
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

			It("should match if one regex in StringCache matches string", func() {
				contains, _ := cache.contains("google.com")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("google.coma")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("agoogle.com")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("www.google.com")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("apple.com")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("apple.de")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("apple.it")
				Expect(contains).Should(BeFalse())
				contains, _ = cache.contains("www.apple.com")
				Expect(contains).Should(BeFalse())
				contains, _ = cache.contains("applecom")
				Expect(contains).Should(BeFalse())
				contains, _ = cache.contains("www.amazon.com")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("amazon.com")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("myamazon.com")
				Expect(contains).Should(BeTrue())
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

			It("should match if one regex in StringCache matches string", func() {
				// first entry
				contains, _ := cache.contains("example.com")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("www.example.com")
				Expect(contains).Should(BeTrue())

				// look alikes
				contains, _ = cache.contains("com")
				Expect(contains).Should(BeFalse())
				contains, _ = cache.contains("example.coma")
				Expect(contains).Should(BeFalse())
				contains, _ = cache.contains("an-example.com")
				Expect(contains).Should(BeFalse())
				contains, _ = cache.contains("examplecom")
				Expect(contains).Should(BeFalse())

				// other entry
				contains, _ = cache.contains("example.org")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("www.example.org")
				Expect(contains).Should(BeTrue())

				// unrelated
				contains, _ = cache.contains("example.net")
				Expect(contains).Should(BeFalse())
				contains, _ = cache.contains("www.example.net")
				Expect(contains).Should(BeFalse())

				// third entry
				contains, _ = cache.contains("blocked")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("sub.blocked")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("sub.sub.blocked")
				Expect(contains).Should(BeTrue())
				contains, _ = cache.contains("example.blocked")
				Expect(contains).Should(BeTrue())
			})

			It("should return correct element count", func() {
				Expect(factory.count()).Should(Equal(4))
				Expect(cache.elementCount()).Should(Equal(4))
			})
		})
	})
})
