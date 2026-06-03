package prefetching

import (
	"context"
	"time"

	cache "github.com/0xERR0R/expiration-cache"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Prefetching expiration cache", func() {
	var (
		ctx      context.Context
		cancelFn context.CancelFunc
	)
	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)
	})
	Describe("Basic operations", func() {
		When("string cache was created", func() {
			It("Initial cache should be empty", func() {
				cache := NewPrefetchingCache[string](ctx, PrefetchingOptions[string]{})
				Expect(cache.TotalCount()).Should(Equal(0))
			})
			It("Initial cache should not contain any elements", func() {
				cache := NewPrefetchingCache[string](ctx, PrefetchingOptions[string]{})
				val, expiration := cache.Get("key1")
				Expect(val).Should(BeNil())
				Expect(expiration).Should(Equal(time.Duration(0)))
			})

			It("Should work as cache (basic operations)", func() {
				cache := NewPrefetchingCache[string](ctx, PrefetchingOptions[string]{})
				v := "v1"
				cache.Put("key1", &v, 50*time.Millisecond)

				val, expiration := cache.Get("key1")
				Expect(val).Should(HaveValue(Equal("v1")))
				Expect(expiration.Milliseconds()).Should(BeNumerically("<=", 50))

				Expect(cache.TotalCount()).Should(Equal(1))

				cache.Clear()

				Expect(cache.TotalCount()).Should(Equal(0))
			})
		})
		Context("Prefetching", func() {
			It("Should prefetch element", func() {
				cache := NewPrefetchingCache[string](ctx, PrefetchingOptions[string]{
					Options: cache.Options{
						CleanupInterval: 100 * time.Millisecond,
					},
					PrefetchThreshold: 2,
					PrefetchExpires:   100 * time.Millisecond,
					ReloadFn: func(ctx context.Context, cacheKey string) (*string, time.Duration) {
						v := "v2"

						return &v, 50 * time.Millisecond
					},
				})
				By("put a value and get it again", func() {
					v := "v1"
					cache.Put("key1", &v, 50*time.Millisecond)
					val, expiration := cache.Get("key1")
					Expect(val).Should(HaveValue(Equal("v1")))
					Expect(expiration.Milliseconds()).Should(BeNumerically("<=", 50))

					Expect(cache.TotalCount()).Should(Equal(1))
				})
				By("Get value twice to trigger prefetching", func() {
					val, _ := cache.Get("key1")
					Expect(val).Should(HaveValue(Equal("v1")))

					Eventually(func(g Gomega) {
						val, _ := cache.Get("key1")
						g.Expect(val).Should(HaveValue(Equal("v2")))
					}).Should(Succeed())
				})
			})
			It("Should not prefetch element", func() {
				cache := NewPrefetchingCache[string](ctx, PrefetchingOptions[string]{
					Options: cache.Options{
						CleanupInterval: 100 * time.Millisecond,
					},
					PrefetchThreshold: 2,
					PrefetchExpires:   100 * time.Millisecond,
					ReloadFn: func(ctx context.Context, cacheKey string) (*string, time.Duration) {
						v := "v2"

						return &v, 50 * time.Millisecond
					},
				})
				By("put a value and get it again", func() {
					v := "v1"
					cache.Put("key1", &v, 50*time.Millisecond)
					val, expiration := cache.Get("key1")
					Expect(val).Should(HaveValue(Equal("v1")))
					Expect(expiration.Milliseconds()).Should(BeNumerically("<=", 50))

					Expect(cache.TotalCount()).Should(Equal(1))
				})
				By("Wait for expiration -> the entry should not be prefetched, threshold was not reached", func() {
					Eventually(func(g Gomega) {
						val, _ := cache.Get("key1")
						g.Expect(val).Should(BeNil())
					}, "5s", "500ms").Should(Succeed())
				})
			})
			It("With default config (threshold = 0) should always prefetch", func() {
				cache := NewPrefetchingCache[string](ctx, PrefetchingOptions[string]{
					Options: cache.Options{
						CleanupInterval: 100 * time.Millisecond,
					},
					ReloadFn: func(ctx context.Context, cacheKey string) (*string, time.Duration) {
						v := "v2"

						return &v, 50 * time.Millisecond
					},
				})
				By("put a value and get it again", func() {
					v := "v1"
					cache.Put("key1", &v, 50*time.Millisecond)
					val, expiration := cache.Get("key1")
					Expect(val).Should(HaveValue(Equal("v1")))
					Expect(expiration.Milliseconds()).Should(BeNumerically("<=", 50))
				})
				By("Should return new prefetched value after expiration", func() {
					Eventually(func(g Gomega) {
						val, _ := cache.Get("key1")
						g.Expect(val).Should(HaveValue(Equal("v2")))
					}, "5s").Should(Succeed())
				})
			})
			It("Should call the reload publisher on prefetch reload", func() {
				publishedKey := make(chan string, 1)
				publishedVal := make(chan string, 1)

				c := NewPrefetchingCache[string](ctx, PrefetchingOptions[string]{
					Options: cache.Options{
						CleanupInterval: 100 * time.Millisecond,
					},
					ReloadFn: func(ctx context.Context, cacheKey string) (*string, time.Duration) {
						v := "v2"

						return &v, 50 * time.Millisecond
					},
				})

				c.SetReloadPublisher(func(key string, val *string, _ time.Duration) {
					// non-blocking so the background cleanup goroutine is never blocked
					select {
					case publishedKey <- key:
					default:
					}
					select {
					case publishedVal <- *val:
					default:
					}
				})

				By("put a value and query it (threshold 0 -> always prefetch)", func() {
					v := "v1"
					c.Put("key1", &v, 50*time.Millisecond)
					c.Get("key1")
				})

				By("the reload publisher receives the reloaded entry", func() {
					Eventually(publishedKey, "5s").Should(Receive(Equal("key1")))
					Eventually(publishedVal, "5s").Should(Receive(Equal("v2")))
				})
			})

			It("Should not panic when the reload publisher is cleared with nil", func() {
				c := NewPrefetchingCache[string](ctx, PrefetchingOptions[string]{
					Options: cache.Options{
						CleanupInterval: 100 * time.Millisecond,
					},
					ReloadFn: func(ctx context.Context, cacheKey string) (*string, time.Duration) {
						v := "v2"

						return &v, 50 * time.Millisecond
					},
				})

				// Set then clear: storing &fn for a nil fn would leave a non-nil pointer
				// to a nil func that the cleanup goroutine would call and panic on.
				c.SetReloadPublisher(func(key string, val *string, _ time.Duration) {})
				c.SetReloadPublisher(nil)

				By("put a value and query it (threshold 0 -> always prefetch)", func() {
					v := "v1"
					c.Put("key1", &v, 50*time.Millisecond)
					c.Get("key1")
				})

				By("the entry is still reloaded without the cleared publisher panicking", func() {
					Eventually(func() string {
						val, _ := c.Get("key1")
						if val == nil {
							return ""
						}

						return *val
					}, "5s").Should(Equal("v2"))
				})
			})

			It("Should execute hook functions", func() {
				onPrefetchAfterPutChannel := make(chan int, 10)
				onPrefetchEntryReloaded := make(chan string, 10)
				onnPrefetchCacheHit := make(chan string, 10)
				cache := NewPrefetchingCache[string](ctx, PrefetchingOptions[string]{
					Options: cache.Options{
						CleanupInterval: 100 * time.Millisecond,
					},
					PrefetchThreshold: 2,
					PrefetchExpires:   100 * time.Millisecond,
					ReloadFn: func(ctx context.Context, cacheKey string) (*string, time.Duration) {
						v := "v2"

						return &v, 50 * time.Millisecond
					},
					OnPrefetchAfterPut:      func(newSize int) { onPrefetchAfterPutChannel <- newSize },
					OnPrefetchEntryReloaded: func(key string) { onPrefetchEntryReloaded <- key },
					OnPrefetchCacheHit:      func(key string) { onnPrefetchCacheHit <- key },
				})
				By("put a value", func() {
					v := "v1"
					cache.Put("key1", &v, 50*time.Millisecond)
					Expect(onPrefetchAfterPutChannel).ShouldNot(Receive())
					Expect(onPrefetchEntryReloaded).ShouldNot(Receive())
					Expect(onnPrefetchCacheHit).ShouldNot(Receive())
				})
				By("get a value 3 times to trigger prefetching", func() {
					// first get
					cache.Get("key1")

					Expect(onPrefetchAfterPutChannel).Should(Receive(Equal(1)))
					Expect(onnPrefetchCacheHit).ShouldNot(Receive())
					Expect(onPrefetchEntryReloaded).ShouldNot(Receive())

					// secont get
					val, _ := cache.Get("key1")
					Expect(val).Should(HaveValue(Equal("v1")))

					// third get -> this should trigger prefetching after expiration
					cache.Get("key1")

					// reload was executed
					Eventually(onPrefetchEntryReloaded).Should(Receive(Equal("key1")))
					Expect(onnPrefetchCacheHit).ShouldNot(Receive())
					// has new value
					Eventually(func(g Gomega) {
						val, _ := cache.Get("key1")
						g.Expect(val).Should(HaveValue(Equal("v2")))
					}, "5s").Should(Succeed())

					// prefetch hit
					Eventually(onnPrefetchCacheHit).Should(Receive(Equal("key1")))
				})
			})
		})
	})
})
