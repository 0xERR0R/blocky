# Redis Write-Through Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decouple Redis from resolvers by implementing a write-through cache decorator on `ExpiringCache[T]` and an event bus bridge for blocking state sync.

**Architecture:** `RedisExpiringCache[T]` decorator wraps any `ExpiringCache[T]`, adding async batch writes to Redis and pub/sub sync across instances. `EventBusBridge` connects the local `evt.Bus()` with Redis pub/sub using two distinct event names to prevent feedback loops. Both components are wired at server startup; resolvers never import or reference Redis.

**Tech Stack:** Go, go-redis/v8, miniredis (tests), Ginkgo/Gomega (BDD tests), existing `evt.Bus()` (EventBus library)

**Spec:** `docs/superpowers/specs/2026-03-23-redis-write-through-cache-design.md`

**Task dependency order:** Task 1 first (events). Tasks 2 and 3 can run in parallel (independent components). Tasks 4 and 5 depend on Tasks 2-3 (resolver cleanup). Task 6 depends on Tasks 4-5 (slim redis.go — must be last since resolvers still import it until then). Task 7 depends on all prior (server wiring). Tasks 8-9 are final verification.

---

### Task 1: Add New Event Constants and `BlockingState` Type

**Files:**
- Modify: `evt/events.go`

- [ ] **Step 1: Add new events and struct to `evt/events.go`**

Add after the existing `BlockingEnabledEvent` constant (line 9):

```go
// BlockingStateChanged fires when blocking state changes locally (for Redis bridge).
// Parameter: BlockingState
BlockingStateChanged = "blocking:stateChanged"

// BlockingStateChangedRemote fires when blocking state changes from a remote instance via Redis.
// Parameter: BlockingState
BlockingStateChangedRemote = "blocking:stateChangedRemote"
```

Add at the bottom of the file:

```go
// BlockingState carries the full blocking state for cross-instance sync.
type BlockingState struct {
	Enabled  bool
	Duration time.Duration
	Groups   []string
}
```

Add `"time"` to the imports.

- [ ] **Step 2: Verify it compiles**

Run: `go build ./evt/...`
Expected: success

- [ ] **Step 3: Commit**

```bash
git add evt/events.go
git commit -m "feat: add BlockingStateChanged events and BlockingState type"
```

---

### Task 2: Implement `RedisExpiringCache[T]` Decorator

**Files:**
- Create: `cache/redis.go`
- Create: `cache/redis_test.go`
- Create: `cache/redis_suite_test.go`

Note: No existing `_suite_test.go` exists in `cache/` — we create one.

- [ ] **Step 1: Create test suite file `cache/redis_suite_test.go`**

```go
package cache

import (
	"testing"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func init() {
	log.Silence()
}

func TestCacheSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cache Suite")
}
```

- [ ] **Step 2: Write failing tests for `RedisExpiringCache` in `cache/redis_test.go`**

Test cases:

1. `Put` stores in inner cache AND Redis (after flush interval)
2. `Get` reads from inner cache only (not Redis directly)
3. `Clear` clears inner cache AND Redis keys with prefix
4. Non-blocking send when buffer is full (does not block `Put`)
5. Cross-instance sync: put on instance A → instance B's inner cache populated via pub/sub
6. Echo filtering: own pub/sub messages are not re-processed
7. Startup cache load: pre-populate Redis, new instance loads entries into inner cache
8. Graceful degradation: `Put`/`Get` still work when Redis is unavailable

```go
package cache

import (
	"context"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	expirationcache "github.com/0xERR0R/expiration-cache"
)

var _ = Describe("RedisExpiringCache", func() {
	var (
		redisServer *miniredis.Miniredis
		redisClient *redis.Client
		innerCache  ExpiringCache[[]byte]
		sut         *RedisExpiringCache[[]byte]
		ctx         context.Context
		cancelFn    context.CancelFunc
	)

	defaultOpts := func() RedisOptions[[]byte] {
		return RedisOptions[[]byte]{
			Prefix:        "blocky:cache:",
			Channel:       "blocky_cache_sync",
			Encode:        func(b *[]byte) ([]byte, error) { return *b, nil },
			Decode:        func(b []byte) (*[]byte, error) { return &b, nil },
			BatchSize:     100,
			FlushInterval: 50 * time.Millisecond,
			SendBufSize:   1000,
		}
	}

	BeforeEach(func() {
		var err error
		redisServer, err = miniredis.Run()
		Expect(err).Should(Succeed())
		DeferCleanup(redisServer.Close)

		redisClient = redis.NewClient(&redis.Options{
			Addr: redisServer.Addr(),
		})

		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		innerCache = expirationcache.NewCache[[]byte](ctx, expirationcache.Options{
			CleanupInterval: time.Second,
		})
	})

	Describe("Put", func() {
		BeforeEach(func() {
			var err error
			sut, err = NewRedisExpiringCache(ctx, innerCache, redisClient, defaultOpts())
			Expect(err).Should(Succeed())
		})

		It("should store in inner cache AND Redis", func() {
			val := []byte("test-value")
			sut.Put("key1", &val, 60*time.Second)

			// Inner cache has it immediately
			got, ttl := innerCache.Get("key1")
			Expect(got).ShouldNot(BeNil())
			Expect(*got).Should(Equal(val))
			Expect(ttl).Should(BeNumerically(">", 0))

			// Redis has it after flush
			Eventually(func() bool {
				return redisServer.Exists("blocky:cache:key1")
			}, "1s", "10ms").Should(BeTrue())
		})

		It("should not block when buffer is full", func() {
			opts := defaultOpts()
			opts.FlushInterval = 10 * time.Second // long interval to prevent draining
			opts.SendBufSize = 2                   // tiny buffer

			sut2, err := NewRedisExpiringCache(ctx, innerCache, redisClient, opts)
			Expect(err).Should(Succeed())

			val := []byte("v")
			done := make(chan struct{})
			go func() {
				defer close(done)
				for i := 0; i < 10; i++ {
					sut2.Put("key", &val, time.Minute)
				}
			}()

			// Must complete quickly, not block
			Eventually(done, "1s").Should(BeClosed())
		})
	})

	Describe("Get", func() {
		BeforeEach(func() {
			var err error
			sut, err = NewRedisExpiringCache(ctx, innerCache, redisClient, defaultOpts())
			Expect(err).Should(Succeed())
		})

		It("should read from inner cache only", func() {
			// Put directly in Redis, not through decorator
			redisServer.Set("blocky:cache:direct", "data")

			// Get returns nil (not in inner cache)
			got, _ := sut.Get("direct")
			Expect(got).Should(BeNil())
		})
	})

	Describe("Clear", func() {
		BeforeEach(func() {
			var err error
			sut, err = NewRedisExpiringCache(ctx, innerCache, redisClient, defaultOpts())
			Expect(err).Should(Succeed())
		})

		It("should clear inner cache AND Redis keys", func() {
			val := []byte("test")
			sut.Put("key1", &val, time.Minute)

			Eventually(func() bool {
				return redisServer.Exists("blocky:cache:key1")
			}, "1s", "10ms").Should(BeTrue())

			sut.Clear()

			Expect(sut.TotalCount()).Should(Equal(0))
			Expect(redisServer.Exists("blocky:cache:key1")).Should(BeFalse())
		})
	})

	Describe("Cross-instance sync", func() {
		It("should populate inner cache from pub/sub messages of another instance", func() {
			innerCache2 := expirationcache.NewCache[[]byte](ctx, expirationcache.Options{
				CleanupInterval: time.Second,
			})

			_, err := NewRedisExpiringCache(ctx, innerCache, redisClient, defaultOpts())
			Expect(err).Should(Succeed())

			redisClient2 := redis.NewClient(&redis.Options{
				Addr: redisServer.Addr(),
			})

			_, err = NewRedisExpiringCache(ctx, innerCache2, redisClient2, defaultOpts())
			Expect(err).Should(Succeed())

			val := []byte("shared-value")
			sut.Put("shared-key", &val, time.Minute)

			Eventually(func() *[]byte {
				v, _ := innerCache2.Get("shared-key")
				return v
			}, "2s", "10ms").ShouldNot(BeNil())
		})

		It("should not re-process own pub/sub messages", func() {
			sut, err := NewRedisExpiringCache(ctx, innerCache, redisClient, defaultOpts())
			Expect(err).Should(Succeed())

			val := []byte("my-value")
			sut.Put("my-key", &val, time.Minute)

			// Wait for flush to complete
			Eventually(func() bool {
				return redisServer.Exists("blocky:cache:my-key")
			}, "1s", "10ms").Should(BeTrue())

			// Verify count stays at 1 (no echo doubling)
			Consistently(func() int {
				return sut.TotalCount()
			}, "200ms", "20ms").Should(Equal(1))
		})
	})

	Describe("Startup cache load", func() {
		It("should load existing Redis entries into inner cache on creation", func() {
			val := []byte("pre-existing")
			redisClient.Set(ctx, "blocky:cache:preloaded", val, time.Minute)

			sut, err := NewRedisExpiringCache(ctx, innerCache, redisClient, defaultOpts())
			Expect(err).Should(Succeed())
			_ = sut

			got, _ := innerCache.Get("preloaded")
			Expect(got).ShouldNot(BeNil())
			Expect(*got).Should(Equal(val))
		})
	})

	Describe("Graceful degradation", func() {
		It("should still work as local cache when Redis is unavailable", func() {
			// Stop Redis server
			redisServer.Close()

			// Create with dead Redis — should not error fatally
			deadClient := redis.NewClient(&redis.Options{
				Addr: "127.0.0.1:0",
			})

			localCache := expirationcache.NewCache[[]byte](ctx, expirationcache.Options{
				CleanupInterval: time.Second,
			})

			sut, err := NewRedisExpiringCache(ctx, localCache, deadClient, defaultOpts())
			Expect(err).Should(Succeed())

			// Put/Get still work locally
			val := []byte("local-only")
			sut.Put("local-key", &val, time.Minute)

			got, _ := sut.Get("local-key")
			Expect(got).ShouldNot(BeNil())
			Expect(*got).Should(Equal(val))
		})
	})
})
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./cache/... -run TestCacheSuite -v -count=1`
Expected: FAIL — `NewRedisExpiringCache` and `RedisOptions` do not exist yet.

- [ ] **Step 4: Implement `RedisExpiringCache[T]` in `cache/redis.go`**

```go
package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
	goredis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const (
	defaultBatchSize     = 100
	defaultFlushInterval = 100 * time.Millisecond
	defaultSendBufSize   = 1000
)

type redisCacheEntry struct {
	Key  string
	Data []byte
	TTL  time.Duration
}

type redisSyncMessage struct {
	Entries []redisSyncEntry `json:"e"`
	Client  []byte           `json:"c"`
}

type redisSyncEntry struct {
	Key  string        `json:"k"`
	Data []byte        `json:"d"`
	TTL  time.Duration `json:"t"`
}

// RedisOptions configures the RedisExpiringCache decorator.
type RedisOptions[T any] struct {
	Prefix        string
	Channel       string
	Encode        func(*T) ([]byte, error)
	Decode        func([]byte) (*T, error)
	BatchSize     int
	FlushInterval time.Duration
	SendBufSize   int
}

// RedisExpiringCache decorates an ExpiringCache with Redis write-through and pub/sub sync.
type RedisExpiringCache[T any] struct {
	inner         ExpiringCache[T]
	client        *goredis.Client
	prefix        string
	channel       string
	id            []byte
	encode        func(*T) ([]byte, error)
	decode        func([]byte) (*T, error)
	sendBuf       chan redisCacheEntry
	batchSize     int
	flushInterval time.Duration
	l             *logrus.Entry
}

// NewRedisExpiringCache creates a decorated cache that syncs with Redis.
func NewRedisExpiringCache[T any](
	ctx context.Context,
	inner ExpiringCache[T],
	client *goredis.Client,
	opts RedisOptions[T],
) (*RedisExpiringCache[T], error) {
	if opts.BatchSize <= 0 {
		opts.BatchSize = defaultBatchSize
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = defaultFlushInterval
	}
	if opts.SendBufSize <= 0 {
		opts.SendBufSize = defaultSendBufSize
	}

	id, err := uuid.New().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to generate instance ID: %w", err)
	}

	c := &RedisExpiringCache[T]{
		inner:         inner,
		client:        client,
		prefix:        opts.Prefix,
		channel:       opts.Channel,
		id:            id,
		encode:        opts.Encode,
		decode:        opts.Decode,
		sendBuf:       make(chan redisCacheEntry, opts.SendBufSize),
		batchSize:     opts.BatchSize,
		flushInterval: opts.FlushInterval,
		l:             log.PrefixedLog("redis-cache"),
	}

	// Load existing Redis entries (blocking, before subscription starts)
	c.loadFromRedis(ctx)

	// Start subscription goroutine
	ps := client.Subscribe(ctx, opts.Channel)
	if _, err := ps.Receive(ctx); err != nil {
		c.l.Warnf("failed to subscribe to Redis channel '%s': %s", opts.Channel, err)
	} else {
		go c.subscribeLoop(ctx, ps)
	}

	// Start batch writer goroutine
	go c.batchWriterLoop(ctx)

	return c, nil
}

func (c *RedisExpiringCache[T]) Put(key string, val *T, expiration time.Duration) {
	c.inner.Put(key, val, expiration)

	data, err := c.encode(val)
	if err != nil {
		c.l.Warnf("failed to encode value for key '%s': %s", key, err)
		return
	}

	// Non-blocking send: drop if buffer is full
	select {
	case c.sendBuf <- redisCacheEntry{Key: key, Data: data, TTL: expiration}:
	default:
		c.l.Debug("send buffer full, dropping cache entry for key: ", key)
	}
}

func (c *RedisExpiringCache[T]) Get(key string) (*T, time.Duration) {
	return c.inner.Get(key)
}

func (c *RedisExpiringCache[T]) TotalCount() int {
	return c.inner.TotalCount()
}

func (c *RedisExpiringCache[T]) Clear() {
	c.inner.Clear()

	bgCtx := context.Background()
	iter := c.client.Scan(bgCtx, 0, c.prefix+"*", 0).Iterator()
	pipe := c.client.Pipeline()

	for iter.Next(bgCtx) {
		pipe.Del(bgCtx, iter.Val())
	}

	if err := iter.Err(); err != nil {
		c.l.Warn("error scanning Redis keys for clear: ", err)
	}

	if _, err := pipe.Exec(bgCtx); err != nil {
		c.l.Warn("error deleting Redis keys on clear: ", err)
	}
}

func (c *RedisExpiringCache[T]) loadFromRedis(ctx context.Context) {
	c.l.Debug("loading cache from Redis")

	iter := c.client.Scan(ctx, 0, c.prefix+"*", 0).Iterator()

	for iter.Next(ctx) {
		key := iter.Val()

		data, err := c.client.Get(ctx, key).Bytes()
		if err != nil {
			c.l.Warn("error reading Redis key: ", err)
			continue
		}

		ttl, err := c.client.TTL(ctx, key).Result()
		if err != nil || ttl <= 0 {
			continue
		}

		val, err := c.decode(data)
		if err != nil {
			c.l.Warn("error decoding Redis value for key: ", key, " ", err)
			continue
		}

		cleanKey := strings.TrimPrefix(key, c.prefix)
		c.inner.Put(cleanKey, val, ttl)
	}

	if err := iter.Err(); err != nil {
		c.l.Warn("error scanning Redis on startup: ", err)
	}
}

func (c *RedisExpiringCache[T]) batchWriterLoop(ctx context.Context) {
	ticker := time.NewTicker(c.flushInterval)
	defer ticker.Stop()

	var batch []redisCacheEntry

	flush := func() {
		if len(batch) == 0 {
			return
		}
		c.flushBatch(ctx, batch)
		batch = batch[:0]
	}

	for {
		select {
		case entry := <-c.sendBuf:
			batch = append(batch, entry)
			if len(batch) >= c.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			// Drain remaining buffer on shutdown
		drainLoop:
			for {
				select {
				case entry := <-c.sendBuf:
					batch = append(batch, entry)
				default:
					break drainLoop
				}
			}
			if len(batch) > 0 {
				c.flushBatch(context.Background(), batch)
			}
			return
		}
	}
}

func (c *RedisExpiringCache[T]) flushBatch(ctx context.Context, batch []redisCacheEntry) {
	pipe := c.client.Pipeline()

	syncEntries := make([]redisSyncEntry, 0, len(batch))

	for _, e := range batch {
		pipe.Set(ctx, c.prefix+e.Key, e.Data, e.TTL)
		syncEntries = append(syncEntries, redisSyncEntry{
			Key:  e.Key,
			Data: e.Data,
			TTL:  e.TTL,
		})
	}

	msg := redisSyncMessage{
		Entries: syncEntries,
		Client:  c.id,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		c.l.Warn("error marshaling sync message: ", err)
	} else {
		pipe.Publish(ctx, c.channel, msgBytes)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		c.l.Warn("error flushing batch to Redis: ", err)
	}
}

func (c *RedisExpiringCache[T]) subscribeLoop(ctx context.Context, ps *goredis.PubSub) {
	ch := ps.Channel()

	for {
		select {
		case msg := <-ch:
			if msg == nil || len(msg.Payload) == 0 {
				continue
			}
			c.processMessage(msg.Payload)
		case <-ctx.Done():
			ps.Close()
			return
		}
	}
}

func (c *RedisExpiringCache[T]) processMessage(payload string) {
	var msg redisSyncMessage
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		c.l.Warn("error unmarshaling sync message: ", err)
		return
	}

	if bytes.Equal(msg.Client, c.id) {
		return
	}

	for _, entry := range msg.Entries {
		val, err := c.decode(entry.Data)
		if err != nil {
			c.l.Warn("error decoding synced entry: ", err)
			continue
		}
		c.inner.Put(entry.Key, val, entry.TTL)
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./cache/... -run TestCacheSuite -v -count=1`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add cache/redis.go cache/redis_test.go cache/redis_suite_test.go
git commit -m "feat: implement RedisExpiringCache decorator with batch write-through and pub/sub sync"
```

---

### Task 3: Implement `EventBusBridge`

Can run in parallel with Task 2.

**Files:**
- Create: `redis/event_bridge.go`
- Create: `redis/event_bridge_test.go`

- [ ] **Step 1: Write failing tests for `EventBusBridge` in `redis/event_bridge_test.go`**

**Important:** The `evt.Bus()` is a global singleton. Tests must clean up subscriptions via `DeferCleanup` to avoid leaking handlers between tests.

```go
package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/0xERR0R/blocky/evt"
	"github.com/alicebob/miniredis/v2"
	goredis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("EventBusBridge", func() {
	var (
		redisServer *miniredis.Miniredis
		redisClient *goredis.Client
		ctx         context.Context
		cancelFn    context.CancelFunc
	)

	BeforeEach(func() {
		var err error
		redisServer, err = miniredis.Run()
		Expect(err).Should(Succeed())
		DeferCleanup(redisServer.Close)

		redisClient = goredis.NewClient(&goredis.Options{
			Addr: redisServer.Addr(),
		})

		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)
	})

	Describe("Local event to Redis", func() {
		It("should publish BlockingStateChanged to Redis", func() {
			bridge, err := NewEventBusBridge(ctx, redisClient)
			Expect(err).Should(Succeed())
			DeferCleanup(func() { bridge.Close() })

			evt.Bus().Publish(evt.BlockingStateChanged, evt.BlockingState{
				Enabled:  false,
				Duration: 5 * time.Minute,
				Groups:   []string{"ads"},
			})

			Eventually(func() map[string]int {
				return redisServer.PubSubNumSub(EventBridgeChannel)
			}).Should(HaveLen(1))
		})
	})

	Describe("Redis message to local event", func() {
		It("should fire BlockingStateChangedRemote on local bus", func() {
			bridge, err := NewEventBusBridge(ctx, redisClient)
			Expect(err).Should(Succeed())
			DeferCleanup(func() { bridge.Close() })

			received := make(chan evt.BlockingState, 1)
			err = evt.Bus().Subscribe(evt.BlockingStateChangedRemote, func(state evt.BlockingState) {
				received <- state
			})
			Expect(err).Should(Succeed())
			DeferCleanup(func() {
				evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, func(state evt.BlockingState) {})
			})

			otherId, _ := uuid.New().MarshalBinary()
			msg := bridgeMessage{
				State:  evt.BlockingState{Enabled: true},
				Client: otherId,
			}
			data, _ := json.Marshal(msg)
			redisServer.Publish(EventBridgeChannel, string(data))

			Eventually(received, "1s").Should(Receive(Equal(evt.BlockingState{Enabled: true})))
		})

		It("should NOT fire for own messages (echo filtering)", func() {
			bridge, err := NewEventBusBridge(ctx, redisClient)
			Expect(err).Should(Succeed())
			DeferCleanup(func() { bridge.Close() })

			received := make(chan evt.BlockingState, 1)
			err = evt.Bus().Subscribe(evt.BlockingStateChangedRemote, func(state evt.BlockingState) {
				received <- state
			})
			Expect(err).Should(Succeed())

			msg := bridgeMessage{
				State:  evt.BlockingState{Enabled: false},
				Client: bridge.id,
			}
			data, _ := json.Marshal(msg)
			redisServer.Publish(EventBridgeChannel, string(data))

			Consistently(received, "200ms").ShouldNot(Receive())
		})

		It("should preserve duration and groups in round-trip", func() {
			bridge, err := NewEventBusBridge(ctx, redisClient)
			Expect(err).Should(Succeed())
			DeferCleanup(func() { bridge.Close() })

			received := make(chan evt.BlockingState, 1)
			err = evt.Bus().Subscribe(evt.BlockingStateChangedRemote, func(state evt.BlockingState) {
				received <- state
			})
			Expect(err).Should(Succeed())

			otherId, _ := uuid.New().MarshalBinary()
			expected := evt.BlockingState{
				Enabled:  false,
				Duration: 10 * time.Minute,
				Groups:   []string{"ads", "tracking"},
			}
			msg := bridgeMessage{
				State:  expected,
				Client: otherId,
			}
			data, _ := json.Marshal(msg)
			redisServer.Publish(EventBridgeChannel, string(data))

			Eventually(received, "1s").Should(Receive(Equal(expected)))
		})
	})
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./redis/... -run "EventBusBridge" -v -count=1`
Expected: FAIL — types don't exist yet.

- [ ] **Step 3: Implement `EventBusBridge` in `redis/event_bridge.go`**

```go
package redis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/log"
	goredis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const EventBridgeChannel = "blocky_sync_enabled"

type bridgeMessage struct {
	State  evt.BlockingState `json:"s"`
	Client []byte            `json:"c"`
}

type EventBusBridge struct {
	client  *goredis.Client
	id      []byte
	channel string
	l       *logrus.Entry
}

func NewEventBusBridge(ctx context.Context, client *goredis.Client) (*EventBusBridge, error) {
	id, err := uuid.New().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to generate bridge ID: %w", err)
	}

	b := &EventBusBridge{
		client:  client,
		id:      id,
		channel: EventBridgeChannel,
		l:       log.PrefixedLog("redis-event-bridge"),
	}

	if err := evt.Bus().Subscribe(evt.BlockingStateChanged, b.onLocalStateChanged); err != nil {
		return nil, fmt.Errorf("failed to subscribe to %s: %w", evt.BlockingStateChanged, err)
	}

	ps := client.Subscribe(ctx, b.channel)
	if _, err := ps.Receive(ctx); err != nil {
		b.l.Warnf("failed to subscribe to Redis channel '%s': %s", b.channel, err)
	} else {
		go b.subscribeLoop(ctx, ps)
	}

	return b, nil
}

// Close unsubscribes from the local event bus.
func (b *EventBusBridge) Close() {
	evt.Bus().Unsubscribe(evt.BlockingStateChanged, b.onLocalStateChanged)
}

func (b *EventBusBridge) onLocalStateChanged(state evt.BlockingState) {
	msg := bridgeMessage{
		State:  state,
		Client: b.id,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		b.l.Warn("error marshaling bridge message: ", err)
		return
	}

	if err := b.client.Publish(context.Background(), b.channel, data).Err(); err != nil {
		b.l.Warn("error publishing to Redis: ", err)
	}
}

func (b *EventBusBridge) subscribeLoop(ctx context.Context, ps *goredis.PubSub) {
	ch := ps.Channel()

	for {
		select {
		case msg := <-ch:
			if msg == nil || len(msg.Payload) == 0 {
				continue
			}
			b.processMessage(msg.Payload)
		case <-ctx.Done():
			ps.Close()
			return
		}
	}
}

func (b *EventBusBridge) processMessage(payload string) {
	var msg bridgeMessage
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		b.l.Warn("error unmarshaling bridge message: ", err)
		return
	}

	if bytes.Equal(msg.Client, b.id) {
		return
	}

	b.l.Debug("received remote blocking state change: ", msg.State)
	evt.Bus().Publish(evt.BlockingStateChangedRemote, msg.State)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./redis/... -run "EventBusBridge" -v -count=1`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add redis/event_bridge.go redis/event_bridge_test.go
git commit -m "feat: implement EventBusBridge for blocking state sync via Redis"
```

---

### Task 4: Remove Redis from `CachingResolver`

**Files:**
- Modify: `resolver/caching_resolver.go`
- Modify: `resolver/caching_resolver_test.go`

- [ ] **Step 1: Modify `CachingResolver` to use a `CacheDecorator` instead of `*redis.Client`**

In `resolver/caching_resolver.go`:

1. Remove `import "github.com/0xERR0R/blocky/redis"` (line 16).
2. Remove `redisClient *redis.Client` field from struct (line 57).
3. Add type alias near the top:
   ```go
   // CacheDecorator optionally wraps the result cache (e.g., with Redis sync).
   type CacheDecorator func(cache.ExpiringCache[[]byte]) (cache.ExpiringCache[[]byte], error)
   ```
4. Change `NewCachingResolver` signature:
   - Before: `NewCachingResolver(ctx, cfg, redis *redis.Client)`
   - After: `NewCachingResolver(ctx, cfg, decorator CacheDecorator)`
5. Change `newCachingResolver` similarly.
6. Replace the redis startup block (lines 86-89) with decorator application:
   ```go
   if decorator != nil {
       decorated, err := decorator(c.resultCache)
       if err != nil {
           return nil, fmt.Errorf("failed to apply cache decorator: %w", err)
       }
       c.resultCache = decorated
   }
   ```
7. Remove `redisSubscriber()` method entirely (lines 178-194).
8. Remove `publish bool` parameter from `putInCache` (line 325):
   ```go
   func (r *CachingResolver) putInCache(ctx context.Context, cacheKey string, response *model.Response, ttl time.Duration) {
   ```
9. Remove the redis publishing block at the end of `putInCache` (lines 347-350).
10. Update call in `Resolve` (line 241):
    ```go
    r.putInCache(ctx, cacheKey, response, cacheTTL)
    ```
    Remove the old call with `false` in `redisSubscriber` too (already deleted).

Note: `configureCaches()` stays — it creates the inner cache with prefetching and metric callbacks. The decorator wraps it after creation, preserving the prefetching circular dependency resolution.

- [ ] **Step 2: Update `resolver/caching_resolver_test.go`**

1. Remove `import "github.com/0xERR0R/blocky/redis"` and `import "github.com/alicebob/miniredis/v2"`.
2. Remove the `"Redis is configured"` Describe block entirely — now tested in `cache/redis_test.go`.
3. Update all `NewCachingResolver` / `newCachingResolver` calls:
   - Where previously `nil` was passed for redis, now pass `nil` for decorator:
     ```go
     sut, _ = NewCachingResolver(ctx, sutConfig, nil)
     ```

- [ ] **Step 3: Run tests**

Run: `go test ./resolver/... -run "CachingResolver" -v -count=1`
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add resolver/caching_resolver.go resolver/caching_resolver_test.go
git commit -m "refactor: remove Redis dependency from CachingResolver, use CacheDecorator"
```

---

### Task 5: Remove Redis from `BlockingResolver` and Subscribe to Remote Events

**Files:**
- Modify: `resolver/blocking_resolver.go`
- Modify: `resolver/blocking_resolver_test.go`

- [ ] **Step 1: Modify `BlockingResolver`**

In `resolver/blocking_resolver.go`:

1. Remove `import "github.com/0xERR0R/blocky/redis"` (line 27).
2. Remove `redisClient *redis.Client` field (line 97).
3. Change `NewBlockingResolver` signature:
   - Before: `NewBlockingResolver(ctx, cfg, redis *redis.Client, bootstrap)`
   - After: `NewBlockingResolver(ctx, cfg, bootstrap)`
4. Remove `redisClient: redis` from struct init (line 155).
5. Remove the redis subscriber startup (lines 164-166).
6. Remove `redisSubscriber()` method entirely (lines 178-201).
7. Subscribe to `BlockingStateChangedRemote`. Add after the existing `SubscribeOnce`:
   ```go
   err = evt.Bus().Subscribe(evt.BlockingStateChangedRemote, func(state evt.BlockingState) {
       if state.Enabled {
           res.internalEnableBlocking()
       } else {
           if disableErr := res.internalDisableBlocking(ctx, state.Duration, state.Groups); disableErr != nil {
               log.PrefixedLog("blocking").Warn("blocking couldn't be disabled: ", disableErr)
           }
       }
   })
   if err != nil {
       return nil, fmt.Errorf("failed to subscribe to %s: %w", evt.BlockingStateChangedRemote, err)
   }
   ```
8. Modify `EnableBlocking` (lines 227-233):
   ```go
   func (r *BlockingResolver) EnableBlocking(ctx context.Context) {
       // internalEnableBlocking publishes BlockingEnabledEvent (for metrics)
       r.internalEnableBlocking()
       // BlockingStateChanged is picked up by EventBusBridge (if Redis configured)
       evt.Bus().Publish(evt.BlockingStateChanged, evt.BlockingState{Enabled: true})
   }
   ```
9. Modify `DisableBlocking` (lines 247-258):
   ```go
   func (r *BlockingResolver) DisableBlocking(ctx context.Context, duration time.Duration, disableGroups []string) error {
       // internalDisableBlocking publishes BlockingEnabledEvent (for metrics)
       err := r.internalDisableBlocking(ctx, duration, disableGroups)
       if err == nil {
           // BlockingStateChanged is picked up by EventBusBridge (if Redis configured)
           evt.Bus().Publish(evt.BlockingStateChanged, evt.BlockingState{
               Enabled:  false,
               Duration: duration,
               Groups:   disableGroups,
           })
       }
       return err
   }
   ```

**Important:** `internalEnableBlocking()` (line 243) and `internalDisableBlocking()` (line 284) already publish `evt.BlockingEnabledEvent` for metrics. Do NOT remove those — they are required for `metrics/metrics_event_publisher.go` compatibility.

- [ ] **Step 2: Update `resolver/blocking_resolver_test.go`**

1. Remove `import "github.com/0xERR0R/blocky/redis"` and `import "github.com/alicebob/miniredis/v2"`.
2. Remove the `"Redis is configured"` Describe block entirely.
3. Add new tests for event bus integration:
   ```go
   Describe("Remote blocking state via event bus", func() {
       When("BlockingStateChangedRemote with enabled=true is received", func() {
           It("should enable blocking", func() {
               sut.DisableBlocking(ctx, 0, []string{})
               Expect(sut.BlockingStatus().Enabled).Should(BeFalse())

               evt.Bus().Publish(evt.BlockingStateChangedRemote, evt.BlockingState{Enabled: true})

               Eventually(func() bool {
                   return sut.BlockingStatus().Enabled
               }).Should(BeTrue())
           })
       })
       When("BlockingStateChangedRemote with enabled=false is received", func() {
           It("should disable blocking", func() {
               evt.Bus().Publish(evt.BlockingStateChangedRemote, evt.BlockingState{
                   Enabled: false,
                   Groups:  []string{},
               })

               Eventually(func() bool {
                   return sut.BlockingStatus().Enabled
               }).Should(BeFalse())
           })
       })
   })
   ```
4. Update all `NewBlockingResolver` calls — remove the Redis parameter:
   - Before: `NewBlockingResolver(ctx, sutConfig, redisClient, systemResolverBootstrap)`
   - After: `NewBlockingResolver(ctx, sutConfig, systemResolverBootstrap)`

- [ ] **Step 3: Run tests**

Run: `go test ./resolver/... -run "BlockingResolver" -v -count=1`
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add resolver/blocking_resolver.go resolver/blocking_resolver_test.go
git commit -m "refactor: remove Redis dependency from BlockingResolver, use event bus for state sync"
```

---

### Task 6: Slim Down `redis/redis.go` to Connection Factory

Now safe to do — no resolver imports `redis` package anymore.

**Files:**
- Modify: `redis/redis.go`
- Modify: `redis/redis_test.go`
- Modify: `redis/redis_suite_test.go`

- [ ] **Step 1: Rewrite `redis/redis.go` as connection factory**

```go
package redis

import (
	"context"
	"fmt"

	"github.com/0xERR0R/blocky/config"
	goredis "github.com/go-redis/redis/v8"
)

// New creates a new Redis connection. Returns nil if Redis is not configured.
func New(ctx context.Context, cfg *config.Redis) (*goredis.Client, error) {
	if cfg == nil || len(cfg.Address) == 0 {
		return nil, nil //nolint:nilnil
	}

	var client *goredis.Client
	if len(cfg.SentinelAddresses) > 0 {
		client = goredis.NewFailoverClient(&goredis.FailoverOptions{
			MasterName:       cfg.Address,
			SentinelUsername: cfg.Username,
			SentinelPassword: cfg.SentinelPassword,
			SentinelAddrs:    cfg.SentinelAddresses,
			Username:         cfg.Username,
			Password:         cfg.Password,
			DB:               cfg.Database,
			MaxRetries:       cfg.ConnectionAttempts,
			MaxRetryBackoff:  cfg.ConnectionCooldown.ToDuration(),
		})
	} else {
		client = goredis.NewClient(&goredis.Options{
			Addr:            cfg.Address,
			Username:        cfg.Username,
			Password:        cfg.Password,
			DB:              cfg.Database,
			MaxRetries:      cfg.ConnectionAttempts,
			MaxRetryBackoff: cfg.ConnectionCooldown.ToDuration(),
		})
	}

	rdb := client.WithContext(ctx)

	if _, err := rdb.Ping(ctx).Result(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis at '%s': %w", cfg.Address, err)
	}

	return rdb, nil
}
```

- [ ] **Step 2: Rewrite `redis/redis_test.go` for connection factory only**

```go
package redis

import (
	"context"

	"github.com/0xERR0R/blocky/config"
	"github.com/alicebob/miniredis/v2"
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Redis connection factory", func() {
	var redisConfig *config.Redis

	BeforeEach(func() {
		var rcfg config.Redis
		Expect(defaults.Set(&rcfg)).Should(Succeed())
		redisConfig = &rcfg
	})

	When("configuration has no address", func() {
		It("should return nil without error", func(ctx context.Context) {
			client, err := New(ctx, redisConfig)
			Expect(err).Should(Succeed())
			Expect(client).Should(BeNil())
		})
	})

	When("configuration has invalid address", func() {
		BeforeEach(func() {
			redisConfig.Address = "127.0.0.1:0"
		})

		It("should fail with error", func(ctx context.Context) {
			_, err := New(ctx, redisConfig)
			Expect(err).Should(HaveOccurred())
		})
	})

	When("sentinel is enabled without servers", func() {
		BeforeEach(func() {
			redisConfig.Address = "test"
			redisConfig.SentinelAddresses = []string{"127.0.0.1:0"}
		})

		It("should fail with error", func(ctx context.Context) {
			_, err := New(ctx, redisConfig)
			Expect(err).Should(HaveOccurred())
		})
	})

	When("configuration has valid address", func() {
		var redisServer *miniredis.Miniredis

		BeforeEach(func() {
			var err error
			redisServer, err = miniredis.Run()
			Expect(err).Should(Succeed())
			DeferCleanup(redisServer.Close)

			redisConfig.Address = redisServer.Addr()
		})

		It("should return a connected client", func(ctx context.Context) {
			client, err := New(ctx, redisConfig)
			Expect(err).Should(Succeed())
			Expect(client).ShouldNot(BeNil())
		})
	})

	When("configuration has invalid password", func() {
		BeforeEach(func() {
			redisServer, err := miniredis.Run()
			Expect(err).Should(Succeed())
			DeferCleanup(redisServer.Close)

			redisServer.RequireAuth("correct-password")

			redisConfig.Address = redisServer.Addr()
			redisConfig.Password = "wrong"
		})

		It("should fail with error", func(ctx context.Context) {
			_, err := New(ctx, redisConfig)
			Expect(err).Should(HaveOccurred())
		})
	})
})
```

- [ ] **Step 3: Simplify `redis/redis_suite_test.go`**

```go
package redis

import (
	"testing"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func init() {
	log.Silence()
}

func TestRedisClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Redis Suite")
}
```

- [ ] **Step 4: Run all Redis tests**

Run: `go test ./redis/... -v -count=1`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add redis/redis.go redis/redis_test.go redis/redis_suite_test.go
git commit -m "refactor: slim redis package to connection factory, remove cache/pub-sub logic"
```

---

### Task 7: Update Server Wiring

**Files:**
- Modify: `server/server.go`

- [ ] **Step 1: Update imports and `createQueryResolver`**

In `server/server.go`:

1. Add import: `"github.com/0xERR0R/blocky/cache"`.
2. Keep `"github.com/0xERR0R/blocky/redis"` import (for `redis.New` and `redis.NewEventBusBridge`).
3. Add import alias: `goredis "github.com/go-redis/redis/v8"` (needed since `redis.New` now returns `*goredis.Client`).

4. Update Redis client creation in `NewServer` (lines 131-137):
   ```go
   var redisConn *goredis.Client
   if cfg.Redis.IsEnabled() {
       redisConn, err = redis.New(ctx, &cfg.Redis)
       if err != nil && cfg.Redis.Required {
           return nil, fmt.Errorf("failed to create required Redis client: %w", err)
       }
   }
   ```

5. Remove `redisClient` parameter from `createQueryResolver` (line 301).

6. Pass `redisConn` to `createQueryResolver` (still needed for cache decorator and bridge):
   ```go
   queryResolver, queryError := createQueryResolver(ctx, cfg, bootstrap, redisConn)
   ```

7. In `createQueryResolver`, build the cache decorator and event bridge:
   ```go
   func createQueryResolver(
       ctx context.Context,
       cfg *config.Config,
       bootstrap *resolver.Bootstrap,
       redisConn *goredis.Client,
   ) (resolver.ChainedResolver, error) {
       // Build cache decorator if Redis is configured
       var cacheDecorator resolver.CacheDecorator
       if redisConn != nil {
           cacheDecorator = func(inner cache.ExpiringCache[[]byte]) (cache.ExpiringCache[[]byte], error) {
               return cache.NewRedisExpiringCache(ctx, inner, redisConn, cache.RedisOptions[[]byte]{
                   Prefix:  "blocky:cache:",
                   Channel: "blocky_cache_sync",
                   Encode:  func(b *[]byte) ([]byte, error) { return *b, nil },
                   Decode:  func(b []byte) (*[]byte, error) { return &b, nil },
               })
           }
       }

       upstreamTree, utErr := resolver.NewUpstreamTreeResolver(ctx, cfg.Upstreams, bootstrap)
       blocking, blErr := resolver.NewBlockingResolver(ctx, cfg.Blocking, bootstrap)
       clientNames, cnErr := resolver.NewClientNamesResolver(ctx, cfg.ClientLookup, cfg.Upstreams, bootstrap)
       queryLogging, qlErr := resolver.NewQueryLoggingResolver(ctx, cfg.QueryLog)
       condUpstream, cuErr := resolver.NewConditionalUpstreamResolver(ctx, cfg.Conditional, cfg.Upstreams, bootstrap)
       hostsFile, hfErr := resolver.NewHostsFileResolver(ctx, cfg.HostsFile, bootstrap)
       cachingResolver, crErr := resolver.NewCachingResolver(ctx, cfg.Caching, cacheDecorator)
       dnssecResolver, dsErr := resolver.NewDNSSECResolver(ctx, cfg.DNSSEC, upstreamTree)

       // Start event bridge for blocking state sync
       if redisConn != nil {
           if _, err := redis.NewEventBusBridge(ctx, redisConn); err != nil {
               logger().Warn("failed to create Redis event bridge: ", err)
           }
       }

       // ... rest of function unchanged (multiErr, Chain, etc.)
   ```

- [ ] **Step 2: Verify compilation**

Run: `go build ./...`
Expected: success

- [ ] **Step 3: Run all tests**

Run: `go test ./... -count=1`
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add server/server.go
git commit -m "refactor: wire Redis cache decorator and event bridge in server startup"
```

---

### Task 8: Verify E2E Tests

**Files:**
- Possibly modify: `e2e/redis_test.go`

- [ ] **Step 1: Run E2E tests**

The E2E tests use real Redis containers and test at the application level. External behavior hasn't changed.

Run: `go test ./e2e/... -run "Redis" -v -count=1 -timeout 120s`
Expected: PASS

If any test needs updating, adapt accordingly and commit.

---

### Task 9: Clean Up and Full Verification

- [ ] **Step 1: Run go mod tidy**

Run: `go mod tidy`

- [ ] **Step 2: Run linter**

Run: `golangci-lint run ./...`
Expected: no new issues

- [ ] **Step 3: Run full test suite**

Run: `go test ./... -count=1`
Expected: all PASS

- [ ] **Step 4: Verify no Redis imports in resolver package**

Run: `grep -r "blocky/redis" resolver/`
Expected: no matches

- [ ] **Step 5: Commit cleanup**

```bash
git add go.mod go.sum
git commit -m "chore: tidy dependencies after Redis refactoring"
```
