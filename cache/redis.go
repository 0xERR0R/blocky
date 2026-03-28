package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/metrics"
	blockredis "github.com/0xERR0R/blocky/redis"
	goredis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

const (
	defaultBatchSize     = 100
	defaultFlushInterval = 100 * time.Millisecond
	defaultSendBufSize   = 1000
	redisScanCount       = 100
	drainTimeout         = 5 * time.Second
)

//nolint:gochecknoglobals
var redisBufferDrops = promauto.With(metrics.Reg).NewCounter(
	prometheus.CounterOpts{
		Name: "blocky_redis_cache_buffer_drops_total",
		Help: "Number of cache entries dropped because the Redis send buffer was full",
	},
)

// RedisOptions configures the RedisExpiringCache decorator.
type RedisOptions[T any] struct {
	// Prefix is prepended to all Redis keys.
	Prefix string
	// Channel is the pub/sub channel name used for cross-instance sync.
	Channel string
	// Encode serializes a cache value to bytes.
	Encode func(*T) ([]byte, error)
	// Decode deserializes bytes back to a cache value.
	Decode func([]byte) (*T, error)
	// BatchSize is the maximum number of entries per Redis pipeline flush.
	BatchSize int
	// FlushInterval is the maximum time between flushes.
	FlushInterval time.Duration
	// SendBufSize is the capacity of the internal send buffer channel.
	SendBufSize int
}

type redisSyncEntry struct {
	Key  string `json:"k"`
	Data []byte `json:"d"`
}

type redisSyncMessage struct {
	Entries []redisSyncEntry `json:"e"`
	Client  string           `json:"c"`
}

type sendBufferEntry[T any] struct {
	key        string
	val        *T
	expiration time.Duration
}

// RedisExpiringCache wraps an ExpiringCache[T] with transparent Redis
// write-through and pub/sub synchronisation across instances.
type RedisExpiringCache[T any] struct {
	inner      ExpiringCache[T]
	client     *goredis.Client
	opts       RedisOptions[T]
	instanceID string
	sendBuf    chan sendBufferEntry[T]
	logger     *logrus.Entry
}

// NewRedisExpiringByteCache creates a RedisExpiringCache for []byte values,
// using identity encode/decode when no codec is provided.
func NewRedisExpiringByteCache(
	ctx context.Context,
	inner ExpiringCache[[]byte],
	client *goredis.Client,
	opts RedisOptions[[]byte],
) (*RedisExpiringCache[[]byte], error) {
	if opts.Encode == nil && opts.Decode == nil {
		opts.Encode = func(b *[]byte) ([]byte, error) { return *b, nil }
		opts.Decode = func(b []byte) (*[]byte, error) {
			cp := make([]byte, len(b))
			copy(cp, b)

			return &cp, nil
		}
	}

	return NewRedisExpiringCache(ctx, inner, client, opts)
}

// NewRedisExpiringCache creates a new RedisExpiringCache decorator.
//
// It performs a blocking startup scan of existing Redis keys and loads them
// into inner before launching the background writer and subscriber goroutines.
// The goroutines run until ctx is cancelled.
func NewRedisExpiringCache[T any](
	ctx context.Context,
	inner ExpiringCache[T],
	client *goredis.Client,
	opts RedisOptions[T],
) (*RedisExpiringCache[T], error) {
	if opts.Encode == nil || opts.Decode == nil {
		return nil, errors.New("RedisOptions: Encode and Decode must both be set")
	}

	if opts.BatchSize <= 0 {
		opts.BatchSize = defaultBatchSize
	}

	if opts.FlushInterval <= 0 {
		opts.FlushInterval = defaultFlushInterval
	}

	if opts.SendBufSize <= 0 {
		opts.SendBufSize = defaultSendBufSize
	}

	c := &RedisExpiringCache[T]{
		inner:      inner,
		client:     client,
		opts:       opts,
		instanceID: uuid.NewString(),
		sendBuf:    make(chan sendBufferEntry[T], opts.SendBufSize),
		logger:     log.PrefixedLog("redis-cache"),
	}

	// Blocking startup load.
	if err := c.loadFromRedis(ctx); err != nil {
		c.logger.WithError(err).Warn("startup Redis scan failed – starting with empty local cache")
	}

	go c.runSubscriber(ctx)
	go c.runWriter(ctx)

	return c, nil
}

// Put stores the value in the inner cache immediately, then enqueues a
// non-blocking send to Redis. If the send buffer is full the entry is dropped
// and a warning is logged – the DNS path is never blocked.
func (c *RedisExpiringCache[T]) Put(key string, val *T, expiration time.Duration) {
	c.inner.Put(key, val, expiration)

	if expiration <= 0 {
		return
	}

	entry := sendBufferEntry[T]{key: key, val: val, expiration: expiration}

	select {
	case c.sendBuf <- entry:
	default:
		redisBufferDrops.Inc()
		c.logger.Warn("redis send buffer full, dropping cache entry")
	}
}

// Get reads from the inner cache only.
func (c *RedisExpiringCache[T]) Get(key string) (*T, time.Duration) {
	return c.inner.Get(key)
}

// TotalCount delegates to the inner cache.
func (c *RedisExpiringCache[T]) TotalCount() int {
	return c.inner.TotalCount()
}

const clearTimeout = 10 * time.Second

// Clear removes all entries from the inner cache and from Redis (all keys
// matching the configured prefix).
func (c *RedisExpiringCache[T]) Clear() {
	c.inner.Clear()

	ctx, cancel := context.WithTimeout(context.Background(), clearTimeout)
	defer cancel()

	err := c.scanKeys(ctx, func(ctx context.Context, keys []string) error {
		return c.client.Del(ctx, keys...).Err()
	})
	if err != nil {
		c.logger.WithError(err).Warn("Redis Clear failed")
	}
}

// redisKey returns the prefixed Redis key for the given cache key.
func (c *RedisExpiringCache[T]) redisKey(key string) string {
	return c.opts.Prefix + key
}

// scanKeys iterates over all Redis keys matching the configured prefix
// and calls fn for each batch of keys returned by SCAN.
func (c *RedisExpiringCache[T]) scanKeys(
	ctx context.Context, fn func(ctx context.Context, keys []string) error,
) error {
	pattern := c.opts.Prefix + "*"

	var cursor uint64

	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, redisScanCount).Result()
		if err != nil {
			return fmt.Errorf("SCAN: %w", err)
		}

		if len(keys) > 0 {
			if err := fn(ctx, keys); err != nil {
				return err
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return nil
}

// loadFromRedis scans existing Redis keys and populates the inner cache.
// It uses a pipeline per SCAN page to minimise round trips.
func (c *RedisExpiringCache[T]) loadFromRedis(ctx context.Context) error {
	return c.scanKeys(ctx, func(ctx context.Context, keys []string) error {
		if err := c.loadKeysViaPipeline(ctx, keys); err != nil {
			c.logger.WithError(err).Warn("pipeline load failed for SCAN page")
		}

		return nil
	})
}

// loadKeysViaPipeline fetches TTL and value for a batch of keys in a single pipeline round trip.
func (c *RedisExpiringCache[T]) loadKeysViaPipeline(ctx context.Context, keys []string) error {
	pipe := c.client.Pipeline()

	ttlCmds := make([]*goredis.DurationCmd, len(keys))
	getCmds := make([]*goredis.StringCmd, len(keys))

	for i, rk := range keys {
		ttlCmds[i] = pipe.TTL(ctx, rk)
		getCmds[i] = pipe.Get(ctx, rk)
	}

	if _, err := pipe.Exec(ctx); err != nil && ctx.Err() == nil {
		return fmt.Errorf("pipeline exec: %w", err)
	}

	for i, rk := range keys {
		dur, err := ttlCmds[i].Result()
		if err != nil || dur <= 0 {
			continue
		}

		data, err := getCmds[i].Bytes()
		if err != nil {
			continue
		}

		val, err := c.opts.Decode(data)
		if err != nil {
			c.logger.WithError(err).Warn("failed to decode Redis entry on startup")

			continue
		}

		cacheKey := strings.TrimPrefix(rk, c.opts.Prefix)
		c.inner.Put(cacheKey, val, dur)
	}

	return nil
}

// runWriter is the background goroutine that drains sendBuf and flushes
// batches to Redis via a pipeline + a single PUBLISH.
func (c *RedisExpiringCache[T]) runWriter(ctx context.Context) {
	ticker := time.NewTicker(c.opts.FlushInterval)
	defer ticker.Stop()

	batch := make([]sendBufferEntry[T], 0, c.opts.BatchSize)

	flush := func(fctx context.Context) {
		if len(batch) == 0 {
			return
		}

		c.flushBatch(fctx, batch)
		batch = make([]sendBufferEntry[T], 0, c.opts.BatchSize)
	}

	for {
		select {
		case entry := <-c.sendBuf:
			batch = append(batch, entry)
			if len(batch) >= c.opts.BatchSize {
				flush(ctx)
			}

		case <-ticker.C:
			flush(ctx)

		case <-ctx.Done():
			drainCtx, drainCancel := context.WithTimeout(context.Background(), drainTimeout)

			// Drain remaining buffer before exiting.
		drainLoop:
			for {
				select {
				case entry := <-c.sendBuf:
					batch = append(batch, entry)
					if len(batch) >= c.opts.BatchSize {
						flush(drainCtx) //nolint:contextcheck
					}
				default:
					break drainLoop
				}
			}

			flush(drainCtx) //nolint:contextcheck
			drainCancel()

			return
		}
	}
}

// flushBatch writes a slice of entries to Redis via a pipeline and publishes a
// single sync message on the configured channel.
func (c *RedisExpiringCache[T]) flushBatch(ctx context.Context, batch []sendBufferEntry[T]) {
	syncEntries := make([]redisSyncEntry, 0, len(batch))

	pipe := c.client.Pipeline()

	for _, e := range batch {
		data, err := c.opts.Encode(e.val)
		if err != nil {
			c.logger.WithError(err).Warn("failed to encode cache entry for Redis")

			continue
		}

		pipe.Set(ctx, c.redisKey(e.key), data, e.expiration)

		syncEntries = append(syncEntries, redisSyncEntry{
			Key:  e.key,
			Data: data,
		})
	}

	if _, err := pipe.Exec(ctx); err != nil && ctx.Err() == nil {
		c.logger.WithError(err).Warn("Redis pipeline exec failed")
	}

	if len(syncEntries) == 0 || c.opts.Channel == "" {
		return
	}

	msg := redisSyncMessage{
		Entries: syncEntries,
		Client:  c.instanceID,
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		c.logger.WithError(err).Warn("failed to marshal sync message")

		return
	}

	if err := c.client.Publish(ctx, c.opts.Channel, payload).Err(); err != nil && ctx.Err() == nil {
		c.logger.WithError(err).Warn("Redis PUBLISH failed")
	}
}

// runSubscriber subscribes to the pub/sub channel and applies remote entries
// to the inner cache, filtering out messages originating from this instance.
// It reconnects automatically on channel closure with exponential backoff.
func (c *RedisExpiringCache[T]) runSubscriber(ctx context.Context) {
	if c.opts.Channel == "" {
		return
	}

	loop := &blockredis.PubSubLoop{
		Client:  c.client,
		Channel: c.opts.Channel,
		Logger:  c.logger,
		Handler: func(ctx context.Context, payload string) {
			c.handleSyncMessage(ctx, []byte(payload))
		},
	}

	loop.Run(ctx)
}

// handleSyncMessage decodes and applies a pub/sub sync message, skipping
// entries that originated from this instance.
func (c *RedisExpiringCache[T]) handleSyncMessage(ctx context.Context, payload []byte) {
	var msg redisSyncMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		c.logger.WithError(err).Warn("failed to decode sync message")

		return
	}

	if msg.Client == c.instanceID {
		return
	}

	pipe := c.client.Pipeline()

	ttlCmds := make([]*goredis.DurationCmd, len(msg.Entries))
	for i, e := range msg.Entries {
		ttlCmds[i] = pipe.TTL(ctx, c.redisKey(e.Key))
	}

	if _, err := pipe.Exec(ctx); err != nil {
		c.logger.WithError(err).Warn("failed to fetch TTLs for sync entries")

		return
	}

	for i, e := range msg.Entries {
		ttl, err := ttlCmds[i].Result()
		if err != nil || ttl <= 0 {
			continue
		}

		val, err := c.opts.Decode(e.Data)
		if err != nil {
			c.logger.WithError(err).Warn("failed to decode sync entry")

			continue
		}

		c.inner.Put(e.Key, val, ttl)
	}
}
