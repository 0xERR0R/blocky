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
})
