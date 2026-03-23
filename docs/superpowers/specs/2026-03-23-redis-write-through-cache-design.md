# Redis Write-Through Cache & Event Bridge

## Problem

Redis concerns are spread across multiple packages. Both `CachingResolver` and `BlockingResolver` directly depend on `*redis.Client`, contain Redis subscription goroutines, and handle Redis-specific message serialization. This coupling makes the resolvers harder to test and reason about.

## Goal

Make Redis transparent to the application. Only the cache layer and a small event bridge should know about Redis. Resolvers interact with the existing `ExpiringCache[T]` interface and the local event bus — nothing else.

## Current Redis Use-Cases

1. **Distributed DNS cache sync** — when a DNS response is cached on one blocky instance, it is stored in Redis and broadcast via pub/sub so other instances populate their local caches.
2. **Blocking state sync** — when blocking is enabled/disabled on one instance, the state change is broadcast to all other instances via Redis pub/sub.

Both use a single Redis channel (`blocky_sync`) with message type discrimination.

## Design

### Component 1: `RedisExpiringCache[T]` Decorator

A decorator implementing `cache.ExpiringCache[T]` that wraps any existing `ExpiringCache[T]` and adds Redis write-through and cross-instance sync.

**Location:** `cache/redis.go`

**Structure:**

```go
type RedisExpiringCache[T any] struct {
    inner         ExpiringCache[T]
    client        *redis.Client       // go-redis low-level client
    prefix        string              // key prefix, e.g. "blocky:cache:"
    channel       string              // pub/sub channel name
    id            []byte              // instance UUID for echo filtering
    encode        func(*T) ([]byte, error)
    decode        func([]byte) (*T, error)
    sendBuf       chan redisCacheEntry // async write buffer
    batchSize     int                 // max entries per flush (e.g. 100)
    flushInterval time.Duration       // max time between flushes (e.g. 100ms)
}
```

**Behavior:**

- `Put(key, val, ttl)` — writes to `inner` cache immediately, then queues entry to `sendBuf` for async Redis write. Uses a **non-blocking send** on `sendBuf`: if the buffer is full, the entry is dropped and a metric counter is incremented. This ensures `Put()` never blocks the DNS resolution path when Redis is slow.
- `Get(key)` — reads from `inner` cache only. The inner cache is kept warm via the subscription goroutine.
- `TotalCount()` — delegates to `inner`.
- `Clear()` — clears `inner` cache AND deletes Redis keys with the configured prefix (via `SCAN` + `DEL` pipeline). This prevents stale entries from being resynced to other instances or on restart.

**Batch writing:**

A background goroutine drains `sendBuf` and flushes in batches using Redis pipelines:

- Flush triggers when batch reaches `batchSize` OR `flushInterval` timer fires — whichever comes first.
- Each flush: pipeline of `SET` commands with TTLs + a single `PUBLISH` containing all entries in the batch.
- Reduces Redis round-trips under load.

**Cross-instance sync:**

A background goroutine subscribes to the Redis pub/sub channel:

- Receives batch messages from other instances.
- Filters out messages from own instance (by UUID).
- Calls `inner.Put()` for each entry to populate the local cache.

**Startup cache load:**

On creation, scans existing Redis keys with the configured prefix, reads values and TTLs, and populates the inner cache via `inner.Put()`. The scan completes **before** the subscription goroutine starts to avoid a race where pub/sub updates could be overwritten by stale scan results.

**Lifecycle:**

The decorator accepts a `context.Context`. On context cancellation:
1. The subscription goroutine stops.
2. The batch writer goroutine flushes any remaining buffered entries, then stops.

### Component 2: Event Bus Bridge

A small component that bridges the local `evt.Bus()` with Redis pub/sub for blocking state synchronization.

**Location:** `redis/event_bridge.go`

**Structure:**

```go
type EventBusBridge struct {
    client  *redis.Client
    id      []byte              // instance UUID for echo filtering
    channel string              // separate channel, e.g. "blocky_sync_enabled"
}
```

**Behavior:**

Two distinct event names prevent feedback loops without flags or mutexes:

- `evt.BlockingStateChanged` — published by `BlockingResolver` when blocking state changes locally. The bridge subscribes to this and forwards to Redis.
- `evt.BlockingStateChangedRemote` — published by the bridge when it receives a state change from Redis. The `BlockingResolver` subscribes to this and applies the change. The bridge does **not** subscribe to this event.

This makes the data flow unidirectional through each event:
```
Local change → BlockingStateChanged → Bridge → Redis
Redis message → Bridge → BlockingStateChangedRemote → BlockingResolver
```

No feedback loop is possible because the bridge only listens to `BlockingStateChanged` and only publishes `BlockingStateChangedRemote` (and vice versa for the resolver).

- **Local → Redis:** Bridge subscribes to `evt.BlockingStateChanged`. When fired, publishes the state to Redis (with instance UUID for cross-instance echo filtering).
- **Redis → Local:** Background goroutine subscribes to the Redis channel. On receiving a message from another instance (filtered by UUID), publishes `evt.BlockingStateChangedRemote` on the local event bus.
- The `BlockingResolver` is unaware of Redis.

**Event payload:**

Both events carry the same struct payload:
```go
type BlockingState struct {
    Enabled  bool
    Duration time.Duration
    Groups   []string
}
```

The existing `evt.BlockingEnabledEvent` (carries only `enabled bool`) is kept unchanged for existing subscribers like `metrics/metrics_event_publisher.go`. `BlockingResolver.EnableBlocking/DisableBlocking` publishes **both** `BlockingEnabledEvent` (for metrics) and `BlockingStateChanged` (for the bridge).

### Component 3: Wiring Changes in `server.go`

**Current flow:**
```
server.go → creates redis.Client → passes to CachingResolver & BlockingResolver
```

**New flow:**
```
server.go → creates go-redis connection (if configured)
           → creates local cache (prefetching or plain ExpiringCache)
           → wraps with RedisExpiringCache decorator (if Redis configured)
           → passes ExpiringCache to CachingResolver (no Redis knowledge)
           → creates BlockingResolver (no Redis parameter)
           → creates EventBusBridge (if Redis configured)
```

### Signature Changes

**`NewCachingResolver`:**
- Before: `NewCachingResolver(ctx, cfg, *redis.Client)`
- After: `NewCachingResolver(ctx, cfg, ExpiringCache[[]byte])`

Cache creation logic (prefetching vs plain, metric callbacks) moves to server wiring or a factory function.

**`NewBlockingResolver`:**
- Before: `NewBlockingResolver(ctx, cfg, *redis.Client, bootstrap)`
- After: `NewBlockingResolver(ctx, cfg, bootstrap)`

### What Gets Removed

**`redis/redis.go` shrinks to a connection factory (~40 lines):**
- Remove: `CacheChannel`, `EnabledChannel`, `CacheMessage`, `EnabledMessage`, `sendBuffer`, `PublishCache()`, `GetRedisCache()`, `processReceivedMessage()`, `convertMessage()`, `getTTL()`, `startup()` goroutine, `bufferMessage` type, `redisMessage` type.
- Keep: `New()` connection factory returning raw `*redis.Client`, sentinel/failover setup.

**`resolver/caching_resolver.go`:**
- Remove: `redisClient` field, `redisSubscriber()` goroutine, `import "github.com/0xERR0R/blocky/redis"`, `publish` bool on `putInCache()`.
- `putInCache()` just calls `r.resultCache.Put()`.

**`resolver/blocking_resolver.go`:**
- Remove: `redisClient` field, `redisSubscriber()` goroutine, `import "github.com/0xERR0R/blocky/redis"`, all `PublishEnabled()` calls.
- Enable/disable just publishes to local event bus (already does this).

## Testing Strategy

**`RedisExpiringCache[T]` (unit tests with miniredis):**
- `Put()` writes to inner cache AND Redis.
- Subscription from another instance populates inner cache.
- Batch flushing: entries are pipelined, not sent individually.
- Echo filtering: own-instance messages are ignored.
- Graceful degradation: if Redis is down, inner cache still works.

**`EventBusBridge` (unit tests with miniredis):**
- Local event → Redis publish.
- Redis message → local event bus publish.
- Own-message filtering.

**Resolver tests (simplified):**
- `CachingResolver` tests inject a plain `ExpiringCache[[]byte]` — no miniredis needed.
- `BlockingResolver` tests verify events on `evt.Bus()` — no miniredis needed.

**E2E tests:**
- Keep existing `e2e/redis_test.go` with real Redis containers.
- Verify full stack: cache sharing between instances, state sync, startup cache loading.

All tests use Ginkgo/Gomega BDD style.

## Rolling Upgrades & Channel Compatibility

The cache decorator uses a new Redis channel name (e.g., `blocky_cache_sync`) and the event bridge uses `blocky_sync_enabled`. The old `blocky_sync` channel with multiplexed message types is no longer used.

During rolling upgrades (mixed old/new instances), old instances will not receive cache sync or state sync from new instances and vice versa. This is acceptable because:
- Cache misses are not failures — they just cause upstream DNS queries.
- Blocking state changes during a rolling upgrade window are rare and transient.

The spec does not attempt backward-compatible message formats. A clean cutover (all instances upgraded together or brief sync gap) is the expected deployment path.

## Graceful Degradation

- **Redis down at startup:** Scan fails, logged as warning. Inner cache starts empty. Subscription goroutine retries via go-redis reconnection. The decorator functions as a plain local cache until Redis recovers.
- **Redis connection drops mid-operation:** Write buffer entries are dropped (non-blocking send already handles this). Subscription is re-established automatically by go-redis. Missed pub/sub messages during the outage are not recovered — this matches current behavior.
- **Redis reconnects:** go-redis re-establishes the connection. The subscription goroutine resumes receiving messages. No explicit re-scan is performed (local cache may have stale entries, but they expire naturally via TTL).

## Scope Exclusions

- Prefetching logic is untouched — stays as local-only behavior.
- No changes to Redis configuration schema.
- No changes to the `ExpiringCache[T]` interface itself.
- Batch size and flush interval are not user-configurable in this iteration (hardcoded sensible defaults).
