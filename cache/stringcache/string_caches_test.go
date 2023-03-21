package stringcache

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Caches", func() {
	Describe("String StringCache", func() {
		When("string StringCache was created", func() {
			factory := newStringCacheFactory()
			factory.addEntry("google.com")
			factory.addEntry("apple.com")
			factory.addEntry("")
			factory.addEntry("google.com")
			factory.addEntry("APPLe.com")

			cache := factory.create()

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
				Expect(cache.elementCount()).Should(Equal(2))
			})
		})
	})

	Describe("Regex StringCache", func() {
		When("regex StringCache was created", func() {
			factory := newRegexCacheFactory()
			factory.addEntry("/.*google.com/")
			factory.addEntry("/^apple\\.(de|com)$/")
			factory.addEntry("/amazon/")
			// this is not a regex, will be ignored
			factory.addEntry("/(wrongRegex/")
			factory.addEntry("plaintext")
			cache := factory.create()
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
