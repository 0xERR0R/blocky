package redis

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/log"
	goredis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const (
	EventBridgeChannel       = "blocky_sync_enabled"
	bridgePublishTimeout     = 5 * time.Second
	bridgeReconnectBaseDelay = 500 * time.Millisecond
	bridgeReconnectMaxDelay  = 30 * time.Second
)

type bridgeMessage struct {
	State  evt.BlockingState `json:"s"`
	Client []byte            `json:"c"`
}

// EventBusBridge connects the local event bus with Redis pub/sub for blocking state synchronization.
type EventBusBridge struct {
	client  *goredis.Client
	id      []byte
	channel string
	l       *logrus.Entry
	cancel  context.CancelFunc
	done    <-chan struct{}
	once    sync.Once
}

// NewEventBusBridge creates a new EventBusBridge that synchronizes blocking state
// between local event bus and Redis pub/sub.
func NewEventBusBridge(ctx context.Context, client *goredis.Client) (*EventBusBridge, error) {
	id, err := uuid.New().MarshalBinary()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)

	b := &EventBusBridge{
		client:  client,
		id:      id,
		channel: EventBridgeChannel,
		l:       log.PrefixedLog("redis-event-bridge"),
		cancel:  cancel,
		done:    ctx.Done(),
	}

	if err := evt.Bus().Subscribe(evt.BlockingStateChanged, b.onLocalStateChanged); err != nil {
		cancel()

		return nil, err
	}

	ps := client.Subscribe(ctx, b.channel)

	if _, err := ps.Receive(ctx); err != nil {
		_ = ps.Close()
		_ = evt.Bus().Unsubscribe(evt.BlockingStateChanged, b.onLocalStateChanged)
		cancel()

		return nil, err
	}

	go b.subscribeLoop(ctx, ps)

	return b, nil
}

// Close stops the subscriber goroutine and unsubscribes from the local event bus.
// It is safe to call multiple times.
func (b *EventBusBridge) Close() error {
	var unsubErr error

	b.once.Do(func() {
		b.cancel()
		unsubErr = evt.Bus().Unsubscribe(evt.BlockingStateChanged, b.onLocalStateChanged)
	})

	return unsubErr
}

// onLocalStateChanged is called when a local blocking state change occurs.
// It marshals the state and publishes it to Redis.
func (b *EventBusBridge) onLocalStateChanged(state evt.BlockingState) {
	msg := bridgeMessage{
		State:  state,
		Client: b.id,
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		b.l.Error("failed to marshal bridge message: ", err)

		return
	}

	pubCtx, cancel := context.WithTimeout(context.Background(), bridgePublishTimeout)
	defer cancel()

	select {
	case <-b.done:
		return
	default:
	}

	if err := b.client.Publish(pubCtx, b.channel, payload).Err(); err != nil {
		b.l.Error("failed to publish to Redis: ", err)
	}
}

// subscribeLoop listens for Redis pub/sub messages and publishes remote state changes
// to the local event bus, filtering out messages from this instance.
// It reconnects automatically on channel closure with exponential backoff.
func (b *EventBusBridge) subscribeLoop(ctx context.Context, ps *goredis.PubSub) {
	defer b.Close()

	for {
		b.consumeMessages(ctx, ps)
		_ = ps.Close()

		if ctx.Err() != nil {
			return
		}

		b.l.Warn("Redis pub/sub channel closed unexpectedly, attempting to reconnect")

		ps = b.reconnect(ctx)
		if ps == nil {
			return
		}
	}
}

// consumeMessages drains messages from the pub/sub channel until it closes or the context is cancelled.
func (b *EventBusBridge) consumeMessages(ctx context.Context, ps *goredis.PubSub) {
	ch := ps.Channel()

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}

			if msg == nil || len(msg.Payload) == 0 {
				continue
			}

			var bm bridgeMessage
			if err := json.Unmarshal([]byte(msg.Payload), &bm); err != nil {
				b.l.Error("failed to unmarshal bridge message: ", err)

				continue
			}

			if bytes.Equal(bm.Client, b.id) {
				continue
			}

			evt.Bus().Publish(evt.BlockingStateChangedRemote, bm.State)

		case <-ctx.Done():
			return
		}
	}
}

// reconnect attempts to re-subscribe with exponential backoff.
// Returns nil if the context is cancelled before reconnecting.
func (b *EventBusBridge) reconnect(ctx context.Context) *goredis.PubSub {
	delay := bridgeReconnectBaseDelay

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}

		ps := b.client.Subscribe(ctx, b.channel)

		if _, err := ps.Receive(ctx); err != nil {
			_ = ps.Close()
			b.l.WithError(err).Warn("Redis pub/sub reconnect failed, retrying")

			delay *= 2
			if delay > bridgeReconnectMaxDelay {
				delay = bridgeReconnectMaxDelay
			}

			continue
		}

		b.l.Info("Redis pub/sub reconnected successfully")

		return ps
	}
}
