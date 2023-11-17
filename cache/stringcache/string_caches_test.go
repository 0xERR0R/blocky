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
				Expect(cache.contains("apple.com")).Should(BeTrue())
				Expect(cache.contains("google.com")).Should(BeTrue())
				Expect(cache.contains("www.google.com")).Should(BeFalse())
				Expect(cache.contains("")).Should(BeFalse())
			})

			It("should match case-insensitive", func() {
				Expect(cache.contains("aPPle.com")).Should(BeTrue())
				Expect(cache.contains("google.COM")).Should(BeTrue())
				Expect(cache.contains("www.google.com")).Should(BeFalse())
				Expect(cache.contains("")).Should(BeFalse())
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
				Expect(cache.contains("google.com")).Should(BeTrue())
				Expect(cache.contains("google.coma")).Should(BeTrue())
				Expect(cache.contains("agoogle.com")).Should(BeTrue())
				Expect(cache.contains("www.google.com")).Should(BeTrue())
				Expect(cache.contains("apple.com")).Should(BeTrue())
				Expect(cache.contains("apple.de")).Should(BeTrue())
				Expect(cache.contains("apple.it")).Should(BeFalse())
				Expect(cache.contains("www.apple.com")).Should(BeFalse())
				Expect(cache.contains("applecom")).Should(BeFalse())
				Expect(cache.contains("www.amazon.com")).Should(BeTrue())
				Expect(cache.contains("amazon.com")).Should(BeTrue())
				Expect(cache.contains("myamazon.com")).Should(BeTrue())
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
				Expect(cache.contains("example.com")).Should(BeTrue())
				Expect(cache.contains("www.example.com")).Should(BeTrue())

				// look alikes
				Expect(cache.contains("com")).Should(BeFalse())
				Expect(cache.contains("example.coma")).Should(BeFalse())
				Expect(cache.contains("an-example.com")).Should(BeFalse())
				Expect(cache.contains("examplecom")).Should(BeFalse())

				// other entry
				Expect(cache.contains("example.org")).Should(BeTrue())
				Expect(cache.contains("www.example.org")).Should(BeTrue())

				// unrelated
				Expect(cache.contains("example.net")).Should(BeFalse())
				Expect(cache.contains("www.example.net")).Should(BeFalse())

				// third entry
				Expect(cache.contains("blocked")).Should(BeTrue())
				Expect(cache.contains("sub.blocked")).Should(BeTrue())
				Expect(cache.contains("sub.sub.blocked")).Should(BeTrue())
				Expect(cache.contains("example.blocked")).Should(BeTrue())
			})

			It("should return correct element count", func() {
				Expect(factory.count()).Should(Equal(4))
				Expect(cache.elementCount()).Should(Equal(4))
			})
		})
	})
})
