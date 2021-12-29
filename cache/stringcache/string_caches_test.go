package stringcache

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Caches", func() {
	Describe("String StringCache", func() {
		When("string StringCache was created", func() {
			factory := newStringCacheFactory()
			factory.AddEntry("google.com")
			factory.AddEntry("apple.com")
			cache := factory.Create()
			It("should match if StringCache Contains string", func() {
				Expect(cache.Contains("apple.com")).Should(BeTrue())
				Expect(cache.Contains("google.com")).Should(BeTrue())
				Expect(cache.Contains("www.google.com")).Should(BeFalse())
				Expect(cache.Contains("")).Should(BeFalse())
			})
			It("should return correct element count", func() {
				Expect(cache.ElementCount()).Should(Equal(2))
			})
		})
	})

	Describe("Regex StringCache", func() {
		When("regex StringCache was created", func() {
			factory := newRegexCacheFactory()
			factory.AddEntry(".*google.com")
			factory.AddEntry("^apple\\.(de|com)$")
			factory.AddEntry("amazon")
			// this is not a regex, will be ignored
			factory.AddEntry("(wrongRegex")
			cache := factory.Create()
			It("should match if one regex in StringCache matches string", func() {
				Expect(cache.Contains("google.com")).Should(BeTrue())
				Expect(cache.Contains("google.coma")).Should(BeTrue())
				Expect(cache.Contains("agoogle.com")).Should(BeTrue())
				Expect(cache.Contains("www.google.com")).Should(BeTrue())
				Expect(cache.Contains("apple.com")).Should(BeTrue())
				Expect(cache.Contains("apple.de")).Should(BeTrue())
				Expect(cache.Contains("apple.it")).Should(BeFalse())
				Expect(cache.Contains("www.apple.com")).Should(BeFalse())
				Expect(cache.Contains("applecom")).Should(BeFalse())
				Expect(cache.Contains("www.amazon.com")).Should(BeTrue())
				Expect(cache.Contains("amazon.com")).Should(BeTrue())
				Expect(cache.Contains("myamazon.com")).Should(BeTrue())
			})
			It("should return correct element count", func() {
				Expect(cache.ElementCount()).Should(Equal(3))
			})
		})
	})

	Describe("Chained StringCache", func() {
		When("chained StringCache was created", func() {
			factory := NewChainedCacheFactory()
			factory.AddEntry("/.*google.com/")
			factory.AddEntry("/^apple\\.(de|com)$/")
			factory.AddEntry("amazon.com")
			cache := factory.Create()
			It("should match if one regex in StringCache matches string", func() {
				Expect(cache.Contains("google.com")).Should(BeTrue())
				Expect(cache.Contains("google.coma")).Should(BeTrue())
				Expect(cache.Contains("agoogle.com")).Should(BeTrue())
				Expect(cache.Contains("www.google.com")).Should(BeTrue())
				Expect(cache.Contains("apple.com")).Should(BeTrue())
				Expect(cache.Contains("amazon.com")).Should(BeTrue())
				Expect(cache.Contains("apple.de")).Should(BeTrue())
				Expect(cache.Contains("www.apple.com")).Should(BeFalse())
				Expect(cache.Contains("applecom")).Should(BeFalse())
			})
			It("should return correct element count", func() {
				Expect(cache.ElementCount()).Should(Equal(3))
			})
		})
	})

})
