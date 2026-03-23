package redis

import (
	"bytes"
	"context"
	"encoding/json"

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

// EventBusBridge connects the local event bus with Redis pub/sub for blocking state synchronization.
type EventBusBridge struct {
	client  *goredis.Client
	id      []byte
	channel string
	l       *logrus.Entry
}

// NewEventBusBridge creates a new EventBusBridge that synchronizes blocking state
// between local event bus and Redis pub/sub.
func NewEventBusBridge(ctx context.Context, client *goredis.Client) (*EventBusBridge, error) {
	id, err := uuid.New().MarshalBinary()
	if err != nil {
		return nil, err
	}

	b := &EventBusBridge{
		client:  client,
		id:      id,
		channel: EventBridgeChannel,
		l:       log.PrefixedLog("redis-event-bridge"),
	}

	if err := evt.Bus().Subscribe(evt.BlockingStateChanged, b.onLocalStateChanged); err != nil {
		return nil, err
	}

	ps := client.Subscribe(ctx, b.channel)

	if _, err := ps.Receive(ctx); err != nil {
		_ = evt.Bus().Unsubscribe(evt.BlockingStateChanged, b.onLocalStateChanged)

		return nil, err
	}

	go b.subscribeLoop(ctx, ps)

	return b, nil
}

// Close unsubscribes from the local event bus.
func (b *EventBusBridge) Close() error {
	return evt.Bus().Unsubscribe(evt.BlockingStateChanged, b.onLocalStateChanged)
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

	if err := b.client.Publish(context.Background(), b.channel, payload).Err(); err != nil {
		b.l.Error("failed to publish to Redis: ", err)
	}
}

// subscribeLoop listens for Redis pub/sub messages and publishes remote state changes
// to the local event bus, filtering out messages from this instance.
func (b *EventBusBridge) subscribeLoop(ctx context.Context, ps *goredis.PubSub) {
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

			// Filter out messages from this instance to avoid feedback loops
			if bytes.Equal(bm.Client, b.id) {
				continue
			}

			evt.Bus().Publish(evt.BlockingStateChangedRemote, bm.State)

		case <-ctx.Done():
			return
		}
	}
}
