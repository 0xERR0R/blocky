package cache

import (
	"context"
	"encoding/json"
	"errors"
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

	Describe("Put with zero expiration", func() {
		When("expiration is zero", func() {
			It("stores in inner but does not enqueue to Redis", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("zero-exp:")

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				c.Put("no-redis", &testValue{Data: "val"}, 0)

				// Inner should not cache it either (expiration <= 0 means no cache)
				val, _ := inner.Get("no-redis")
				Expect(val).To(BeNil())

				// Redis should never get this key
				Consistently(func() bool {
					exists, _ := client.Exists(ctx, "zero-exp:no-redis").Result()

					return exists > 0
				}, "200ms", "50ms").Should(BeFalse())
			})
		})
	})

	Describe("TotalCount", func() {
		When("multiple values are stored", func() {
			It("returns the count from the inner cache", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("count:")

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				c.Put("a", &testValue{Data: "1"}, time.Minute)
				c.Put("b", &testValue{Data: "2"}, time.Minute)
				c.Put("c", &testValue{Data: "3"}, time.Minute)

				Expect(c.TotalCount()).To(Equal(3))
			})
		})
	})

	Describe("handleSyncMessage", func() {
		When("the payload is invalid JSON", func() {
			It("does not add entries to the cache", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("bad-json:")

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				c.handleSyncMessage(ctx, []byte("not-valid-json{{{"))

				Expect(inner.TotalCount()).To(Equal(0))
			})
		})

		When("the message is from the same instance", func() {
			It("skips the message", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("self:")

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				data, _ := encodeTestValue(&testValue{Data: "val"})
				msg := redisSyncMessage{
					Entries: []redisSyncEntry{{Key: "k", Data: data}},
					Client:  c.instanceID,
				}
				payload, _ := json.Marshal(msg)

				c.handleSyncMessage(ctx, payload)

				Expect(inner.TotalCount()).To(Equal(0))
			})
		})

		When("a sync entry has invalid data", func() {
			It("skips the bad entry but processes valid ones", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("bad-entry:")

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				goodData, _ := encodeTestValue(&testValue{Data: "good"})

				// Store keys in Redis so handleSyncMessage can fetch their TTLs.
				client.Set(ctx, "bad-entry:bad", []byte("not-json"), time.Minute)
				client.Set(ctx, "bad-entry:good", goodData, time.Minute)

				msg := redisSyncMessage{
					Entries: []redisSyncEntry{
						{Key: "bad", Data: []byte("not-json")},
						{Key: "good", Data: goodData},
					},
					Client: "other-instance",
				}
				payload, _ := json.Marshal(msg)

				c.handleSyncMessage(ctx, payload)

				Expect(inner.TotalCount()).To(Equal(1))
				val, _ := inner.Get("good")
				Expect(val).ToNot(BeNil())
				Expect(val.Data).To(Equal("good"))
			})
		})
	})

	Describe("flushBatch", func() {
		When("encoding fails for an entry", func() {
			It("skips the bad entry and flushes the rest", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("enc-err:")

				callCount := 0
				opts.Encode = func(v *testValue) ([]byte, error) {
					callCount++
					if v.Data == "fail" {
						return nil, errors.New("encode error")
					}

					return encodeTestValue(v)
				}

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				batch := []sendBufferEntry[testValue]{
					{key: "fail-key", val: &testValue{Data: "fail"}, expiration: time.Minute},
					{key: "ok-key", val: &testValue{Data: "ok"}, expiration: time.Minute},
				}
				c.flushBatch(ctx, batch)

				// Only the "ok" entry should be in Redis
				exists, _ := client.Exists(ctx, "enc-err:ok-key").Result()
				Expect(exists).To(Equal(int64(1)))

				exists, _ = client.Exists(ctx, "enc-err:fail-key").Result()
				Expect(exists).To(Equal(int64(0)))
			})
		})

		When("the channel is empty", func() {
			It("writes to Redis but does not publish sync messages", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("no-chan:")
				opts.Channel = ""

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				batch := []sendBufferEntry[testValue]{
					{key: "k", val: &testValue{Data: "v"}, expiration: time.Minute},
				}
				c.flushBatch(ctx, batch)

				// Entry should still be in Redis
				exists, _ := client.Exists(ctx, "no-chan:k").Result()
				Expect(exists).To(Equal(int64(1)))
			})
		})
	})

	Describe("NewRedisExpiringCache defaults", func() {
		When("options have zero values for batch size, flush interval, and send buf size", func() {
			It("applies defaults", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := RedisOptions[testValue]{
					Prefix:  "defaults:",
					Channel: "defaults-chan",
					Encode:  encodeTestValue,
					Decode:  decodeTestValue,
					// All zero — should get defaults
				}

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				Expect(c.opts.BatchSize).To(Equal(100))
				Expect(c.opts.FlushInterval).To(Equal(100 * time.Millisecond))
				Expect(c.opts.SendBufSize).To(Equal(1000))
			})
		})
	})

	Describe("Clear with scan error", func() {
		When("the Redis connection fails during Clear", func() {
			It("does not panic and clears the inner cache", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("clear-err:")

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				c.Put("foo", &testValue{Data: "bar"}, time.Minute)

				// Close the Redis server to cause scan failure
				srv.Close()

				c.Clear()

				// Inner cache should still be cleared
				Expect(inner.TotalCount()).To(Equal(0))
			})
		})
	})

	Describe("loadKeysViaPipeline with decode errors", func() {
		When("a stored value cannot be decoded", func() {
			It("skips that key and continues", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				// Store a key with bad data directly in Redis
				Expect(client.Set(ctx, "decode-err:bad", "not-valid-json", time.Minute).Err()).ToNot(HaveOccurred())

				// Store a key with good data
				goodData, _ := encodeTestValue(&testValue{Data: "good"})
				Expect(client.Set(ctx, "decode-err:good", goodData, time.Minute).Err()).ToNot(HaveOccurred())

				inner := newTestInner(ctx)
				opts := defaultOpts("decode-err:")

				_, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				// Only the good key should be loaded
				val, _ := inner.Get("good")
				Expect(val).ToNot(BeNil())
				Expect(val.Data).To(Equal("good"))

				// The bad key should be skipped
				badVal, _ := inner.Get("bad")
				Expect(badVal).To(BeNil())
			})
		})
	})

	Describe("runWriter batch size trigger", func() {
		When("enough entries are buffered to fill a batch", func() {
			It("flushes immediately without waiting for the timer", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("batch:")
				opts.BatchSize = 3
				opts.FlushInterval = 10 * time.Minute // prevent timer flush

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				// Put exactly BatchSize entries to trigger immediate flush
				c.Put("a", &testValue{Data: "1"}, time.Minute)
				c.Put("b", &testValue{Data: "2"}, time.Minute)
				c.Put("c", &testValue{Data: "3"}, time.Minute)

				Eventually(func() bool {
					exists, _ := client.Exists(ctx, "batch:a", "batch:b", "batch:c").Result()

					return exists == 3
				}).WithTimeout(2 * time.Second).WithPolling(20 * time.Millisecond).Should(BeTrue())
			})
		})
	})

	Describe("runSubscriber with empty channel", func() {
		When("the Channel option is empty", func() {
			It("does not subscribe to pub/sub", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("no-sub:")
				opts.Channel = ""

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				// Put a value via the cache (will write to Redis but not publish sync)
				c.Put("local", &testValue{Data: "local-only"}, time.Minute)

				val, _ := c.Get("local")
				Expect(val).ToNot(BeNil())
				Expect(val.Data).To(Equal("local-only"))
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

	Describe("handleSyncMessage with TTL fetch failure", func() {
		When("the Redis server is down during TTL fetch", func() {
			It("skips all entries without panic", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("ttl-fail:")

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				goodData, _ := encodeTestValue(&testValue{Data: "val"})

				// Close Redis to cause TTL fetch failure
				srv.Close()

				msg := redisSyncMessage{
					Entries: []redisSyncEntry{{Key: "k", Data: goodData}},
					Client:  "other-instance",
				}
				payload, _ := json.Marshal(msg)

				c.handleSyncMessage(ctx, payload)

				Expect(inner.TotalCount()).To(Equal(0))
			})
		})
	})

	Describe("handleSyncMessage with missing TTL", func() {
		When("a sync entry's key has no expiration in Redis", func() {
			It("skips the entry", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("no-ttl:")

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				data, _ := encodeTestValue(&testValue{Data: "val"})

				// Store key WITHOUT expiration (TTL = -1 in Redis)
				client.Set(ctx, "no-ttl:k", data, 0)

				msg := redisSyncMessage{
					Entries: []redisSyncEntry{{Key: "k", Data: data}},
					Client:  "other-instance",
				}
				payload, _ := json.Marshal(msg)

				c.handleSyncMessage(ctx, payload)

				Expect(inner.TotalCount()).To(Equal(0))
			})
		})
	})

	Describe("flushBatch with publish failure", func() {
		When("the Redis server goes down after entries are written", func() {
			It("does not panic", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := newTestInner(ctx)
				opts := defaultOpts("pub-fail:")

				c, err := NewRedisExpiringCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				// Close Redis so both pipeline exec and publish will fail
				srv.Close()

				batch := []sendBufferEntry[testValue]{
					{key: "k", val: &testValue{Data: "v"}, expiration: time.Minute},
				}
				Expect(func() { c.flushBatch(ctx, batch) }).ToNot(Panic())
			})
		})
	})

	Describe("NewRedisExpiringByteCache", func() {
		When("no codec is provided", func() {
			It("uses identity encode/decode functions", func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)

				inner := expirationcache.NewCache[[]byte](ctx, expirationcache.Options{})

				opts := RedisOptions[[]byte]{
					Prefix:  "bytes:",
					Channel: "bytes-chan",
					// Encode and Decode intentionally nil — defaults should apply
				}

				c, err := NewRedisExpiringByteCache(ctx, inner, client, opts)
				Expect(err).ToNot(HaveOccurred())

				original := []byte("hello world")
				c.Put("test", &original, time.Minute)

				// Wait for Redis write
				Eventually(func() bool {
					exists, _ := client.Exists(ctx, "bytes:test").Result()

					return exists > 0
				}).WithTimeout(2 * time.Second).WithPolling(20 * time.Millisecond).Should(BeTrue())

				// Verify round-trip: read from Redis and decode
				data, err := client.Get(ctx, "bytes:test").Bytes()
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal(original))
			})
		})
	})
})
