package stringcache_test

import (
	"github.com/0xERR0R/blocky/cache/stringcache"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Chained grouped cache", func() {
	var (
		cache   *stringcache.ChainedGroupedCache
		factory stringcache.GroupFactory
	)
	Describe("Empty cache", func() {
		When("empty cache was created", func() {
			BeforeEach(func() {
				cache = stringcache.NewChainedGroupedCache()
			})

			It("should have element count of 0", func() {
				Expect(cache.ElementCount("someGroup")).Should(BeNumerically("==", 0))
			})

			It("should not find any string", func() {
				Expect(cache.Contains("searchString", []string{"someGroup"})).Should(BeEmpty())
			})

			It("should not add entries", func() {
				Expect(cache.Refresh("group").AddEntry("test")).Should(BeFalse())
			})
		})
	})
	Describe("Delegation", func() {
		When("Chained cache contains delegates", func() {
			BeforeEach(func() {
				inMemoryCache1 := stringcache.NewInMemoryGroupedStringCache()
				inMemoryCache2 := stringcache.NewInMemoryGroupedStringCache()
				cache = stringcache.NewChainedGroupedCache(inMemoryCache1, inMemoryCache2)

				factory = cache.Refresh("group1")

				factory.AddEntry("string1")
				factory.AddEntry("string2")
			})

			It("cache should still have 0 element, since finish was not executed", func() {
				Expect(cache.ElementCount("group1")).Should(BeNumerically("==", 0))
			})

			It("factory has 4 elements (both caches)", func() {
				Expect(factory.Count()).Should(BeNumerically("==", 2))
			})

			It("should have element count of 4", func() {
				factory.Finish()
				Expect(cache.ElementCount("group1")).Should(BeNumerically("==", 2))
			})

			It("should find strings and return the matched rule per group", func() {
				factory.Finish()
				Expect(cache.Contains("string1", []string{"group1"})).
					Should(Equal(map[string]string{"group1": "string1"}))
				Expect(cache.Contains("string2", []string{"group1", "someOtherGroup"})).
					Should(Equal(map[string]string{"group1": "string2"}))
			})
		})
	})

	Describe("Multiple sub-caches matching the same group", func() {
		// Mirror the real lists.ListCache composition (regex, wildcard, string).
		// When a domain matches in more than one sub-cache for the same group, a
		// single representative rule is reported: the one from the last (cheapest)
		// cache in construction order. This contract must hold regardless of the
		// internal query order/short-circuiting.
		BeforeEach(func() {
			cache = stringcache.NewChainedGroupedCache(
				stringcache.NewInMemoryGroupedRegexCache(),
				stringcache.NewInMemoryGroupedWildcardCache(),
				stringcache.NewInMemoryGroupedStringCache(),
			)

			factory = cache.Refresh("group1")
			factory.AddEntry(`/^multi\.example$/`) // regex match for multi.example
			factory.AddEntry("*.wild.example")     // wildcard match for x.wild.example
			factory.AddEntry("multi.example")      // exact string match for multi.example
			factory.Finish()
		})

		It("reports the string rule when string, wildcard and regex could all match", func() {
			Expect(cache.Contains("multi.example", []string{"group1"})).
				Should(Equal(map[string]string{"group1": "multi.example"}))
		})

		It("reports the wildcard rule when only wildcard and regex match", func() {
			factory = cache.Refresh("group2")
			factory.AddEntry(`/\.wild\.example$/`) // regex also matches sub.wild.example
			factory.AddEntry("*.wild.example")     // wildcard matches sub.wild.example
			factory.Finish()

			Expect(cache.Contains("sub.wild.example", []string{"group2"})).
				Should(Equal(map[string]string{"group2": "*.wild.example"}))
		})
	})

	Describe("Cache refresh", func() {
		When("cache with 2 groups was created", func() {
			BeforeEach(func() {
				inMemoryCache1 := stringcache.NewInMemoryGroupedStringCache()
				inMemoryCache2 := stringcache.NewInMemoryGroupedStringCache()
				cache = stringcache.NewChainedGroupedCache(inMemoryCache1, inMemoryCache2)

				factory = cache.Refresh("group1")

				factory.AddEntry("g1")
				factory.AddEntry("both")
				factory.Finish()

				factory = cache.Refresh("group2")
				factory.AddEntry("g2")
				factory.AddEntry("both")
				factory.Finish()
			})

			It("should contain 4 elements in 2 groups", func() {
				Expect(cache.ElementCount("group1")).Should(BeNumerically("==", 2))
				Expect(cache.ElementCount("group2")).Should(BeNumerically("==", 2))
				Expect(cache.Contains("g1", []string{"group1", "group2"})).
					Should(Equal(map[string]string{"group1": "g1"}))
				Expect(cache.Contains("g2", []string{"group1", "group2"})).
					Should(Equal(map[string]string{"group2": "g2"}))
				Expect(cache.Contains("both", []string{"group1", "group2"})).
					Should(Equal(map[string]string{"group1": "both", "group2": "both"}))
			})

			It("should replace group content on refresh", func() {
				factory = cache.Refresh("group1")
				factory.AddEntry("newString")
				factory.Finish()

				Expect(cache.ElementCount("group1")).Should(BeNumerically("==", 1))
				Expect(cache.ElementCount("group2")).Should(BeNumerically("==", 2))
				Expect(cache.Contains("g1", []string{"group1", "group2"})).Should(BeEmpty())
				Expect(cache.Contains("newString", []string{"group1", "group2"})).
					Should(Equal(map[string]string{"group1": "newstring"})) // rule is normalized to lower-case
				Expect(cache.Contains("g2", []string{"group1", "group2"})).
					Should(Equal(map[string]string{"group2": "g2"}))
				Expect(cache.Contains("both", []string{"group1", "group2"})).
					Should(Equal(map[string]string{"group2": "both"}))
			})

			It("should replace empty groups on refresh", func() {
				factory = cache.Refresh("group")
				factory.AddEntry("begone")
				factory.Finish()

				Expect(cache.ElementCount("group")).Should(BeNumerically("==", 1))

				factory = cache.Refresh("group")
				factory.Finish()

				Expect(cache.ElementCount("group")).Should(BeNumerically("==", 0))
			})
		})
	})
})
