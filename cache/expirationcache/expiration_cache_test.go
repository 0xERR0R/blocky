package expirationcache

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Expiration cache", func() {
	Describe("Basic operations", func() {
		When("string cache was created", func() {

			It("Initial cache should be empty", func() {
				cache := NewCache()
				Expect(cache.TotalCount()).Should(Equal(0))
			})
			It("Initial cache should not contain any elements", func() {
				cache := NewCache()
				val, expiration := cache.Get("key1")
				Expect(val).Should(BeNil())
				Expect(expiration).Should(Equal(time.Duration(0)))
			})
		})
		When("Put new value with positive TTL", func() {
			It("Should return the value before element expires", func() {
				cache := NewCache(WithCleanUpInterval(100 * time.Millisecond))
				cache.Put("key1", "val1", 50*time.Millisecond)
				val, expiration := cache.Get("key1")
				Expect(val).Should(Equal("val1"))
				Expect(expiration.Milliseconds()).Should(BeNumerically("<=", 50))

				Expect(cache.TotalCount()).Should(Equal(1))
			})
			It("Should return nil after expiration", func() {
				cache := NewCache(WithCleanUpInterval(100 * time.Millisecond))
				cache.Put("key1", "val1", 50*time.Millisecond)

				// wait for expiration
				Eventually(func(g Gomega) {
					val, ttl := cache.Get("key1")
					g.Expect(val).Should(Equal("val1"))
					g.Expect(ttl.Milliseconds()).Should(BeNumerically("==", 0))
				}, "60ms").Should(Succeed())

				Expect(cache.TotalCount()).Should(Equal(0))
				// internal map has still the expired item
				Expect(cache.lru.Len()).Should(Equal(1))

				// wait for cleanup run
				Eventually(func() int {
					return cache.lru.Len()
				}, "100ms").Should(Equal(0))
			})
		})
		When("Put new value without expiration", func() {
			It("Should not cache the value", func() {
				cache := NewCache(WithCleanUpInterval(50 * time.Millisecond))
				cache.Put("key1", "val1", 0)
				val, expiration := cache.Get("key1")
				Expect(val).Should(BeNil())
				Expect(expiration.Milliseconds()).Should(BeNumerically("==", 0))
				Expect(cache.TotalCount()).Should(Equal(0))
			})
		})
		When("Put updated value", func() {
			It("Should return updated value", func() {
				cache := NewCache()
				cache.Put("key1", "val1", 50*time.Millisecond)
				cache.Put("key1", "val2", 200*time.Millisecond)

				val, expiration := cache.Get("key1")

				Expect(val).Should(Equal("val2"))
				Expect(expiration.Milliseconds()).Should(BeNumerically(">", 100))
				Expect(expiration.Milliseconds()).Should(BeNumerically("<=", 200))
				Expect(cache.TotalCount()).Should(Equal(1))
			})
		})
		When("Purging after usage", func() {
			It("Should be empty after purge", func() {
				cache := NewCache()
				cache.Put("key1", "val1", time.Second)

				Expect(cache.TotalCount()).Should(Equal(1))

				cache.Clear()

				Expect(cache.TotalCount()).Should(Equal(0))
			})
		})
	})
	Describe("preExpiration function", func() {
		When(" function is defined", func() {
			It("should update the value and TTL if function returns values", func() {
				fn := func(key string) (val interface{}, ttl time.Duration) {
					return "val2", time.Second
				}
				cache := NewCache(WithOnExpiredFn(fn))
				cache.Put("key1", "val1", 50*time.Millisecond)

				// wait for expiration
				Eventually(func(g Gomega) {
					val, ttl := cache.Get("key1")
					g.Expect(val).Should(Equal("val1"))
					g.Expect(ttl.Milliseconds()).Should(
						BeNumerically("==", 0))
				}, "150ms").Should(Succeed())
			})

			It("should update the value and TTL if function returns values on cleanup if element is expired", func() {
				fn := func(key string) (val interface{}, ttl time.Duration) {
					return "val2", time.Second
				}
				cache := NewCache(WithOnExpiredFn(fn))
				cache.Put("key1", "val1", time.Millisecond)

				time.Sleep(2 * time.Millisecond)

				// trigger cleanUp manually -> onExpiredFn will be executed, because element is expired
				cache.cleanUp()

				// wait for expiration
				val, ttl := cache.Get("key1")
				Expect(val).Should(Equal("val2"))
				Expect(ttl.Milliseconds()).Should(And(
					BeNumerically(">", 900)),
					BeNumerically("<=", 1000))
			})

			It("should delete the key if function returns nil", func() {
				fn := func(key string) (val interface{}, ttl time.Duration) {
					return nil, 0
				}
				cache := NewCache(WithCleanUpInterval(100*time.Millisecond), WithOnExpiredFn(fn))
				cache.Put("key1", "val1", 50*time.Millisecond)

				Eventually(func() (interface{}, time.Duration) {
					return cache.Get("key1")
				}, "200ms").Should(BeNil())
			})

		})
	})
	Describe("LRU behaviour", func() {
		When("Defined max size is reached", func() {
			It("should remove old elements", func() {
				cache := NewCache(WithMaxSize(3))

				cache.Put("key1", "val1", time.Second)
				cache.Put("key2", "val2", time.Second)
				cache.Put("key3", "val3", time.Second)
				cache.Put("key4", "val4", time.Second)

				Expect(cache.TotalCount()).Should(Equal(3))

				// key1 was removed
				Expect(cache.Get("key1")).Should(BeNil())
				// key2,3,4 still in the cache
				Expect(cache.lru.Contains("key2")).Should(BeTrue())
				Expect(cache.lru.Contains("key3")).Should(BeTrue())
				Expect(cache.lru.Contains("key4")).Should(BeTrue())

				// now get key2 to increase usage count
				_, _ = cache.Get("key2")

				// put key5
				cache.Put("key5", "val5", time.Second)

				// now key3 should be removed
				Expect(cache.lru.Contains("key2")).Should(BeTrue())
				Expect(cache.lru.Contains("key3")).Should(BeFalse())
				Expect(cache.lru.Contains("key4")).Should(BeTrue())
				Expect(cache.lru.Contains("key5")).Should(BeTrue())
			})
		})
	})
})
