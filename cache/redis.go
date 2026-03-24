package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	redisScanCount       = 100
	reconnectBaseDelay   = 500 * time.Millisecond
	reconnectMaxDelay    = 30 * time.Second
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

// setBytesCodecDefaults sets identity Encode/Decode when T is []byte.
func setBytesCodecDefaults[T any](opts *RedisOptions[T]) {
	// Runtime type check: only applies when T is []byte.
	if enc, ok := any(&opts.Encode).(*func(*[]byte) ([]byte, error)); ok {
		*enc = func(b *[]byte) ([]byte, error) { return *b, nil }
	}

	if dec, ok := any(&opts.Decode).(*func([]byte) (*[]byte, error)); ok {
		*dec = func(b []byte) (*[]byte, error) { //nolint:unparam
			cp := make([]byte, len(b))
			copy(cp, b)

			return &cp, nil
		}
	}
}

type redisSyncEntry struct {
	Key  string        `json:"k"`
	Data []byte        `json:"d"`
	TTL  time.Duration `json:"t"`
}

type redisSyncMessage struct {
	Entries []redisSyncEntry `json:"e"`
	Client  []byte           `json:"c"` // instance UUID
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
	instanceID []byte
	sendBuf    chan sendBufferEntry[T]
	logger     *logrus.Entry
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
	// Apply defaults: when T is []byte and no codec is provided, use identity.
	if opts.Encode == nil && opts.Decode == nil {
		setBytesCodecDefaults(&opts)
	}

	if opts.Encode == nil || opts.Decode == nil {
		return nil, errors.New("RedisOptions: Encode and Decode must both be set (or both nil for []byte)")
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

	id, err := uuid.New().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("generate instance uuid: %w", err)
	}

	c := &RedisExpiringCache[T]{
		inner:      inner,
		client:     client,
		opts:       opts,
		instanceID: id,
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

	pattern := c.opts.Prefix + "*"

	var cursor uint64

	for {
		var keys []string

		var err error

		keys, cursor, err = c.client.Scan(ctx, cursor, pattern, redisScanCount).Result()
		if err != nil {
			c.logger.WithError(err).Warn("Redis SCAN failed during Clear")

			return
		}

		if len(keys) > 0 {
			if err := c.client.Del(ctx, keys...).Err(); err != nil {
				c.logger.WithError(err).Warn("Redis DEL failed during Clear")
			}
		}

		if cursor == 0 {
			break
		}
	}
}

// redisKey returns the prefixed Redis key for the given cache key.
func (c *RedisExpiringCache[T]) redisKey(key string) string {
	return c.opts.Prefix + key
}

// loadFromRedis scans existing Redis keys and populates the inner cache.
// It uses a pipeline per SCAN page to minimise round trips.
func (c *RedisExpiringCache[T]) loadFromRedis(ctx context.Context) error {
	pattern := c.opts.Prefix + "*"

	var cursor uint64

	for {
		var keys []string

		var err error

		keys, cursor, err = c.client.Scan(ctx, cursor, pattern, redisScanCount).Result()
		if err != nil {
			return fmt.Errorf("SCAN: %w", err)
		}

		if len(keys) > 0 {
			if err := c.loadKeysViaPipeline(ctx, keys); err != nil {
				c.logger.WithError(err).Warn("pipeline load failed for SCAN page")
			}
		}

		if cursor == 0 {
			break
		}
	}

	return nil
}

// loadKeysViaPipeline fetches TTL and value for a batch of keys in two pipeline round trips.
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

	flush := func() {
		if len(batch) == 0 {
			return
		}

		c.flushBatch(ctx, batch)
		batch = make([]sendBufferEntry[T], 0, c.opts.BatchSize)
	}

	for {
		select {
		case entry := <-c.sendBuf:
			batch = append(batch, entry)
			if len(batch) >= c.opts.BatchSize {
				flush()
			}

		case <-ticker.C:
			flush()

		case <-ctx.Done():
			// Drain remaining buffer before exiting.
		drainLoop:
			for {
				select {
				case entry := <-c.sendBuf:
					batch = append(batch, entry)
					if len(batch) >= c.opts.BatchSize {
						flush()
					}
				default:
					break drainLoop
				}
			}

			flush()

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
			TTL:  e.expiration,
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

	sub := c.client.Subscribe(ctx, c.opts.Channel)

	for {
		c.consumeSubscription(ctx, sub)
		_ = sub.Close()

		if ctx.Err() != nil {
			return
		}

		c.logger.Warn("Redis pub/sub channel closed unexpectedly, attempting to reconnect")

		sub = c.reconnectSubscriber(ctx)
		if sub == nil {
			return
		}
	}
}

// consumeSubscription drains messages from the pub/sub channel until it closes or ctx is cancelled.
func (c *RedisExpiringCache[T]) consumeSubscription(ctx context.Context, sub *goredis.PubSub) {
	ch := sub.Channel()

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}

			c.handleSyncMessage([]byte(msg.Payload))

		case <-ctx.Done():
			return
		}
	}
}

// reconnectSubscriber attempts to re-subscribe with exponential backoff.
// Returns nil if the context is cancelled before reconnecting.
func (c *RedisExpiringCache[T]) reconnectSubscriber(ctx context.Context) *goredis.PubSub {
	delay := reconnectBaseDelay

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}

		sub := c.client.Subscribe(ctx, c.opts.Channel)

		if _, err := sub.Receive(ctx); err != nil {
			_ = sub.Close()
			c.logger.WithError(err).Warn("Redis pub/sub reconnect failed, retrying")

			delay *= 2
			if delay > reconnectMaxDelay {
				delay = reconnectMaxDelay
			}

			continue
		}

		c.logger.Info("Redis pub/sub reconnected successfully")

		return sub
	}
}

// handleSyncMessage decodes and applies a pub/sub sync message, skipping
// entries that originated from this instance.
func (c *RedisExpiringCache[T]) handleSyncMessage(payload []byte) {
	var msg redisSyncMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		c.logger.WithError(err).Warn("failed to decode sync message")

		return
	}

	// Filter out messages sent by this instance to prevent echo.
	if bytes.Equal(msg.Client, c.instanceID) {
		return
	}

	for _, e := range msg.Entries {
		val, err := c.opts.Decode(e.Data)
		if err != nil {
			c.logger.WithError(err).Warn("failed to decode sync entry")

			continue
		}

		c.inner.Put(e.Key, val, e.TTL)
	}
}
