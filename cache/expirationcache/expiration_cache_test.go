package expirationcache

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Expiration cache", func() {
	Describe("Basic operations", func() {
		When("string cache was created", func() {
			It("Initial cache should be empty", func() {
				cache := NewCache[string]()
				Expect(cache.TotalCount()).Should(Equal(0))
			})
			It("Initial cache should not contain any elements", func() {
				cache := NewCache[string]()
				val, expiration := cache.Get("key1")
				Expect(val).Should(BeNil())
				Expect(expiration).Should(Equal(time.Duration(0)))
			})
		})
		When("Put new value with positive TTL", func() {
			It("Should return the value before element expires", func() {
				cache := NewCache(WithCleanUpInterval[string](100 * time.Millisecond))
				v := "v1"
				cache.Put("key1", &v, 50*time.Millisecond)
				val, expiration := cache.Get("key1")
				Expect(val).Should(HaveValue(Equal("v1")))
				Expect(expiration.Milliseconds()).Should(BeNumerically("<=", 50))

				Expect(cache.TotalCount()).Should(Equal(1))
			})
			It("Should return nil after expiration", func() {
				cache := NewCache(WithCleanUpInterval[string](100 * time.Millisecond))
				v := "v1"
				cache.Put("key1", &v, 50*time.Millisecond)

				// wait for expiration
				Eventually(func(g Gomega) {
					val, ttl := cache.Get("key1")
					g.Expect(val).Should(HaveValue(Equal("v1")))
					g.Expect(ttl.Milliseconds()).Should(BeNumerically("==", 0))
				}, "100ms").Should(Succeed())

				// wait for cleanup run
				Eventually(func() int {
					return cache.lru.Len()
				}, "100ms").Should(Equal(0))
			})
		})
		When("Put new value without expiration", func() {
			It("Should not cache the value", func() {
				cache := NewCache(WithCleanUpInterval[string](50 * time.Millisecond))
				v := "x"
				cache.Put("key1", &v, 0)
				val, expiration := cache.Get("key1")
				Expect(val).Should(BeNil())
				Expect(expiration.Milliseconds()).Should(BeNumerically("==", 0))
				Expect(cache.TotalCount()).Should(Equal(0))
			})
		})
		When("Put updated value", func() {
			It("Should return updated value", func() {
				cache := NewCache[string]()
				v1 := "v1"
				v2 := "v2"
				cache.Put("key1", &v1, 50*time.Millisecond)
				cache.Put("key1", &v2, 200*time.Millisecond)

				val, expiration := cache.Get("key1")

				Expect(val).Should(HaveValue(Equal("v2")))
				Expect(expiration.Milliseconds()).Should(BeNumerically(">", 100))
				Expect(expiration.Milliseconds()).Should(BeNumerically("<=", 200))
				Expect(cache.TotalCount()).Should(Equal(1))
			})
		})
		When("Purging after usage", func() {
			It("Should be empty after purge", func() {
				cache := NewCache[string]()
				v1 := "y"
				cache.Put("key1", &v1, time.Second)

				Expect(cache.TotalCount()).Should(Equal(1))

				cache.Clear()

				Expect(cache.TotalCount()).Should(Equal(0))
			})
		})
	})
	Describe("preExpiration function", func() {
		When(" function is defined", func() {
			It("should update the value and TTL if function returns values", func() {
				fn := func(key string) (val *string, ttl time.Duration) {
					v2 := "v2"

					return &v2, time.Second
				}
				cache := NewCache(WithOnExpiredFn(fn))
				v1 := "v1"
				cache.Put("key1", &v1, 50*time.Millisecond)

				// wait for expiration
				Eventually(func(g Gomega) {
					val, ttl := cache.Get("key1")
					g.Expect(val).Should(HaveValue(Equal("v1")))
					g.Expect(ttl.Milliseconds()).Should(
						BeNumerically("==", 0))
				}, "150ms").Should(Succeed())
			})

			It("should update the value and TTL if function returns values on cleanup if element is expired", func() {
				fn := func(key string) (val *string, ttl time.Duration) {
					v2 := "val2"

					return &v2, time.Second
				}
				cache := NewCache(WithOnExpiredFn(fn))
				v1 := "somval"
				cache.Put("key1", &v1, time.Millisecond)

				time.Sleep(2 * time.Millisecond)

				// trigger cleanUp manually -> onExpiredFn will be executed, because element is expired
				cache.cleanUp()

				// wait for expiration
				val, ttl := cache.Get("key1")
				Expect(val).Should(HaveValue(Equal("val2")))
				Expect(ttl.Milliseconds()).Should(And(
					BeNumerically(">", 900),
					BeNumerically("<=", 1000)))
			})

			It("should delete the key if function returns nil", func() {
				fn := func(key string) (val *string, ttl time.Duration) {
					return nil, 0
				}
				cache := NewCache(WithCleanUpInterval[string](100*time.Millisecond), WithOnExpiredFn(fn))
				v1 := "z"
				cache.Put("key1", &v1, 50*time.Millisecond)

				Eventually(func() (interface{}, time.Duration) {
					return cache.Get("key1")
				}, "200ms").Should(BeNil())
			})
		})
	})
	Describe("LRU behaviour", func() {
		When("Defined max size is reached", func() {
			It("should remove old elements", func() {
				cache := NewCache(WithMaxSize[string](3))

				v1 := "val1"
				v2 := "val2"
				v3 := "val3"
				v4 := "val4"
				v5 := "val5"

				cache.Put("key1", &v1, time.Second)
				cache.Put("key2", &v2, time.Second)
				cache.Put("key3", &v3, time.Second)
				cache.Put("key4", &v4, time.Second)

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
				cache.Put("key5", &v5, time.Second)

				// now key3 should be removed
				Expect(cache.lru.Contains("key2")).Should(BeTrue())
				Expect(cache.lru.Contains("key3")).Should(BeFalse())
				Expect(cache.lru.Contains("key4")).Should(BeTrue())
				Expect(cache.lru.Contains("key5")).Should(BeTrue())
			})
		})
	})
})
