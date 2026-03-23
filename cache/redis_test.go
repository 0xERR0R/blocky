package cache

import (
	"context"
	"encoding/json"
	"time"

	expirationcache "github.com/0xERR0R/expiration-cache"
	"github.com/alicebob/miniredis/v2"
	goredis "github.com/go-redis/redis/v8"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// testValue is a simple string wrapper used as cache value type in tests.
type testValue struct {
	Data string `json:"data"`
}

func encodeTestValue(v *testValue) ([]byte, error) {
	return json.Marshal(v)
}

func decodeTestValue(b []byte) (*testValue, error) {
	var v testValue
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

// newTestInner creates a fresh in-memory expiration cache.
func newTestInner(ctx context.Context) ExpiringCache[testValue] {
	return expirationcache.NewCache[testValue](ctx, expirationcache.Options{})
}

// defaultOpts returns a RedisOptions with the given prefix suitable for tests.
func defaultOpts(prefix string) RedisOptions[testValue] {
	return RedisOptions[testValue]{
		Prefix:        prefix,
		Channel:       "test-sync-" + prefix,
		Encode:        encodeTestValue,
		Decode:        decodeTestValue,
		BatchSize:     100,
		FlushInterval: 20 * time.Millisecond,
		SendBufSize:   1000,
	}
}

// newRedisClient creates a goredis client pointing at the given miniredis server.
func newRedisClient(srv *miniredis.Miniredis) *goredis.Client {
	return goredis.NewClient(&goredis.Options{Addr: srv.Addr()})
}

var _ = Describe("RedisExpiringCache", func() {
	var (
		srv    *miniredis.Miniredis
		client *goredis.Client
	)

	BeforeEach(func() {
		var err error
		srv, err = miniredis.Run()
		Expect(err).ToNot(HaveOccurred())

		DeferCleanup(srv.Close)

		client = newRedisClient(srv)
		DeferCleanup(client.Close)
	})

	Describe("Put", func() {
		When("a value is stored", func() {
			It("stores in inner AND Redis", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("put:")

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				c.Put("foo", &testValue{Data: "bar"}, time.Minute)

				// Inner cache must have the entry immediately.
				val, _ := inner.Get("foo")
				Expect(val).ToNot(BeNil())
				Expect(val.Data).To(Equal("bar"))

				// Redis key must appear after async flush.
				Eventually(func() bool {
					exists, _ := client.Exists(ctx, "put:foo").Result()

					return exists > 0
				}).WithTimeout(2 * time.Second).WithPolling(20 * time.Millisecond).Should(BeTrue())
			})
		})

		When("the send buffer is full", func() {
			It("completes without blocking", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("full:")
				opts.SendBufSize = 2
				opts.FlushInterval = 10 * time.Minute // prevent flush during test

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				done := make(chan struct{})
				go func() {
					defer close(done)

					for i := 0; i < 10; i++ {
						c.Put("key", &testValue{Data: "v"}, time.Minute)
					}
				}()

				Eventually(done).WithTimeout(time.Second).Should(BeClosed())
			})
		})
	})

	Describe("Get", func() {
		When("a value exists only in Redis (not in inner cache)", func() {
			It("returns nil", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				// Pre-populate Redis with a key under a different prefix so
				// the decorator's startup scan does not pick it up.
				data, _ := encodeTestValue(&testValue{Data: "direct"})
				Expect(client.Set(ctx, "other:foo", data, time.Minute).Err()).ToNot(HaveOccurred())

				// Create decorator with a prefix that does NOT match the key above.
				innerEmpty := newTestInner(ctx)
				optsEmpty := defaultOpts("get-empty:")

				c, err := NewRedisExpiringCache(ctx, innerEmpty, client, optsEmpty)
				Expect(err).ToNot(HaveOccurred())

				val, _ := c.Get("foo")
				Expect(val).To(BeNil())
			})
		})
	})

	Describe("Clear", func() {
		When("entries exist in both inner cache and Redis", func() {
			It("clears both", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("clear:")

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				c.Put("foo", &testValue{Data: "bar"}, time.Minute)

				// Wait for Redis write.
				Eventually(func() bool {
					exists, _ := client.Exists(ctx, "clear:foo").Result()

					return exists > 0
				}).WithTimeout(2 * time.Second).WithPolling(20 * time.Millisecond).Should(BeTrue())

				c.Clear()

				Expect(inner.TotalCount()).To(Equal(0))

				keys, err := client.Keys(ctx, "clear:*").Result()
				Expect(err).ToNot(HaveOccurred())
				Expect(keys).To(BeEmpty())
			})
		})
	})

	Describe("Cross-instance sync", func() {
		When("two instances share the same Redis", func() {
			It("propagates Put from instance1 to instance2's inner cache", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				sharedOpts := defaultOpts("sync:")
				sharedOpts.FlushInterval = 10 * time.Millisecond

				inner1 := newTestInner(ctx)
				c1, err := NewRedisExpiringCache(ctx, inner1, client, sharedOpts)
				Expect(err).ToNot(HaveOccurred())

				inner2 := newTestInner(ctx)
				c2, err := NewRedisExpiringCache(ctx, inner2, client, sharedOpts)
				Expect(err).ToNot(HaveOccurred())

				_ = c2 // used via inner2

				c1.Put("shared", &testValue{Data: "hello"}, time.Minute)

				Eventually(func() *testValue {
					val, _ := inner2.Get("shared")

					return val
				}).WithTimeout(3 * time.Second).WithPolling(20 * time.Millisecond).ShouldNot(BeNil())
			})
		})
	})

	Describe("Echo filtering", func() {
		When("an instance publishes a message", func() {
			It("does not double-count the entry in its own cache", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("echo:")
				opts.FlushInterval = 10 * time.Millisecond

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				c.Put("key", &testValue{Data: "v"}, time.Minute)

				// Wait for the flush to happen.
				Eventually(func() bool {
					exists, _ := client.Exists(ctx, "echo:key").Result()

					return exists > 0
				}).WithTimeout(2 * time.Second).WithPolling(10 * time.Millisecond).Should(BeTrue())

				// TotalCount must remain 1, not grow due to echo.
				Consistently(func() int {
					return c.TotalCount()
				}, "300ms", "30ms").Should(Equal(1))
			})
		})
	})

	Describe("Startup cache load", func() {
		When("Redis already contains keys with the configured prefix", func() {
			It("loads those entries into the inner cache on creation", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				data, _ := encodeTestValue(&testValue{Data: "pre-existing"})
				Expect(client.Set(ctx, "load:existing", data, time.Minute).Err()).ToNot(HaveOccurred())

				inner := newTestInner(ctx)
				opts := defaultOpts("load:")

				_, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				val, _ := inner.Get("existing")
				Expect(val).ToNot(BeNil())
				Expect(val.Data).To(Equal("pre-existing"))
			})
		})
	})

	Describe("Graceful degradation", func() {
		When("the Redis client points to a dead server", func() {
			It("Put and Get still work locally", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				deadClient := goredis.NewClient(&goredis.Options{
					Addr:        "127.0.0.1:0",
					DialTimeout: 50 * time.Millisecond,
					ReadTimeout: 50 * time.Millisecond,
				})
				DeferCleanup(deadClient.Close)

				inner := newTestInner(ctx)
				opts := defaultOpts("dead:")

				// Startup scan will fail but should not return error (just log).
				c, err := NewRedisExpiringCache(ctx, inner, deadClient, opts)
				Expect(err).ToNot(HaveOccurred())

				c.Put("local", &testValue{Data: "value"}, time.Minute)

				val, _ := c.Get("local")
				Expect(val).ToNot(BeNil())
				Expect(val.Data).To(Equal("value"))
			})
		})
	})
})
