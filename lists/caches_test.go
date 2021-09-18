package lists

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Caches", func() {
	Describe("String cache", func() {
		When("string cache was created", func() {
			factory := newStringCacheFactory()
			factory.addEntry("google.com")
			factory.addEntry("apple.com")
			cache := factory.create()
			It("should match if cache contains string", func() {
				Expect(cache.contains("apple.com")).Should(BeTrue())
				Expect(cache.contains("google.com")).Should(BeTrue())
				Expect(cache.contains("www.google.com")).Should(BeFalse())
			})
			It("should return correct element count", func() {
				Expect(cache.elementCount()).Should(Equal(2))
			})
		})
	})

	Describe("Regex cache", func() {
		When("regex cache was created", func() {
			factory := newRegexCacheFactory()
			factory.addEntry(".*google.com")
			factory.addEntry("^apple\\.(de|com)$")
			factory.addEntry("amazon")
			// this is not a regex, will be ignored
			factory.addEntry("(wrongRegex")
			cache := factory.create()
			It("should match if one regex in cache matches string", func() {
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
				Expect(cache.elementCount()).Should(Equal(3))
			})
		})
	})

	Describe("Chained cache", func() {
		When("chained cache was created", func() {
			factory := newChainedCacheFactory()
			factory.addEntry("/.*google.com/")
			factory.addEntry("/^apple\\.(de|com)$/")
			factory.addEntry("amazon.com")
			cache := factory.create()
			It("should match if one regex in cache matches string", func() {
				Expect(cache.contains("google.com")).Should(BeTrue())
				Expect(cache.contains("google.coma")).Should(BeTrue())
				Expect(cache.contains("agoogle.com")).Should(BeTrue())
				Expect(cache.contains("www.google.com")).Should(BeTrue())
				Expect(cache.contains("apple.com")).Should(BeTrue())
				Expect(cache.contains("amazon.com")).Should(BeTrue())
				Expect(cache.contains("apple.de")).Should(BeTrue())
				Expect(cache.contains("www.apple.com")).Should(BeFalse())
				Expect(cache.contains("applecom")).Should(BeFalse())
			})
			It("should return correct element count", func() {
				Expect(cache.elementCount()).Should(Equal(3))
			})
		})
	})

})
