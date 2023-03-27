package stringcache_test

import (
	"github.com/0xERR0R/blocky/cache/stringcache"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("In-Memory grouped cache", func() {
	Describe("Empty cache", func() {
		When("empty cache was created", func() {
			cache := stringcache.NewInMemoryGroupedStringCache()

			It("should have element count of 0", func() {
				Expect(cache.ElementCount("someGroup")).Should(BeNumerically("==", 0))
			})

			It("should not find any string", func() {
				Expect(cache.Contains("searchString", []string{"someGroup"})).Should(BeEmpty())
			})
		})
		When("cache with one empty group", func() {
			cache := stringcache.NewInMemoryGroupedStringCache()
			factory := cache.Refresh("group1")
			factory.Finish()

			It("should have element count of 0", func() {
				Expect(cache.ElementCount("group1")).Should(BeNumerically("==", 0))
			})

			It("should not find any string", func() {
				Expect(cache.Contains("searchString", []string{"group1"})).Should(BeEmpty())
			})
		})

	})
	Describe("Cache creation", func() {
		When("cache with 1 group was created", func() {
			cache := stringcache.NewInMemoryGroupedStringCache()

			factory := cache.Refresh("group1")

			factory.AddEntry("string1")
			factory.AddEntry("string2")

			It("cache should still have 0 element, since finish was not executed", func() {
				Expect(cache.ElementCount("group1")).Should(BeNumerically("==", 0))
			})

			It("factory has 2 elements", func() {
				Expect(factory.Count()).Should(BeNumerically("==", 2))
			})

			It("should have element count of 2", func() {
				factory.Finish()
				Expect(cache.ElementCount("group1")).Should(BeNumerically("==", 2))
			})

			It("should find strings", func() {
				Expect(cache.Contains("string1", []string{"group1"})).Should(ConsistOf("group1"))
				Expect(cache.Contains("string2", []string{"group1", "someOtherGroup"})).Should(ConsistOf("group1"))
			})
		})
		When("String grouped cache is used", func() {
			cache := stringcache.NewInMemoryGroupedStringCache()
			factory := cache.Refresh("group1")

			factory.AddEntry("string1")
			factory.AddEntry("/string2/")
			factory.Finish()

			It("should ignore regex", func() {
				Expect(cache.ElementCount("group1")).Should(BeNumerically("==", 1))
				Expect(cache.Contains("string1", []string{"group1"})).Should(ConsistOf("group1"))
			})
		})
		When("Regex grouped cache is used", func() {
			cache := stringcache.NewInMemoryGroupedRegexCache()
			factory := cache.Refresh("group1")

			factory.AddEntry("string1")
			factory.AddEntry("/string2/")
			factory.Finish()

			It("should ignore non-regex", func() {
				Expect(cache.ElementCount("group1")).Should(BeNumerically("==", 1))
				Expect(cache.Contains("string1", []string{"group1"})).Should(BeEmpty())
				Expect(cache.Contains("string2", []string{"group1"})).Should(ConsistOf("group1"))
				Expect(cache.Contains("shouldalsomatchstring2", []string{"group1"})).Should(ConsistOf("group1"))
			})
		})
	})

	Describe("Cache refresh", func() {
		When("cache with 2 groups was created", func() {
			cache := stringcache.NewInMemoryGroupedStringCache()

			factory := cache.Refresh("group1")

			factory.AddEntry("g1")
			factory.AddEntry("both")
			factory.Finish()

			factory = cache.Refresh("group2")
			factory.AddEntry("g2")
			factory.AddEntry("both")
			factory.Finish()

			It("should contain 4 elements in 2 groups", func() {
				Expect(cache.ElementCount("group1")).Should(BeNumerically("==", 2))
				Expect(cache.ElementCount("group2")).Should(BeNumerically("==", 2))
				Expect(cache.Contains("g1", []string{"group1", "group2"})).Should(ConsistOf("group1"))
				Expect(cache.Contains("g2", []string{"group1", "group2"})).Should(ConsistOf("group2"))
				Expect(cache.Contains("both", []string{"group1", "group2"})).Should(ConsistOf("group1", "group2"))
			})

			It("Should replace group content on refresh", func() {
				factory := cache.Refresh("group1")
				factory.AddEntry("newString")
				factory.Finish()

				Expect(cache.ElementCount("group1")).Should(BeNumerically("==", 1))
				Expect(cache.ElementCount("group2")).Should(BeNumerically("==", 2))
				Expect(cache.Contains("g1", []string{"group1", "group2"})).Should(BeEmpty())
				Expect(cache.Contains("newString", []string{"group1", "group2"})).Should(ConsistOf("group1"))
				Expect(cache.Contains("g2", []string{"group1", "group2"})).Should(ConsistOf("group2"))
				Expect(cache.Contains("both", []string{"group1", "group2"})).Should(ConsistOf("group2"))
			})
		})

	})
})
