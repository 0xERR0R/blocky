package redis

import (
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
	EventBridgeChannel   = "blocky_sync_enabled"
	bridgePublishTimeout = 5 * time.Second
)

type bridgeMessage struct {
	State  evt.BlockingState `json:"s"`
	Client string            `json:"c"`
}

// EventBusBridge connects the local event bus with Redis pub/sub for blocking state synchronization.
type EventBusBridge struct {
	client  *goredis.Client
	id      string
	channel string
	l       *logrus.Entry
	cancel  context.CancelFunc
	done    <-chan struct{}
	once    sync.Once
}

// NewEventBusBridge creates a new EventBusBridge that synchronizes blocking state
// between local event bus and Redis pub/sub.
func NewEventBusBridge(ctx context.Context, client *goredis.Client) (*EventBusBridge, error) {
	ctx, cancel := context.WithCancel(ctx)

	b := &EventBusBridge{
		client:  client,
		id:      uuid.NewString(),
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

	loop := &PubSubLoop{
		Client:  client,
		Channel: b.channel,
		Logger:  b.l,
		Handler: b.handleMessage,
	}

	go func() {
		defer b.Close()

		loop.RunWithSub(ctx, ps)
	}()

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

// handleMessage processes a single Redis pub/sub message, publishing remote
// state changes to the local event bus and filtering out echoes.
func (b *EventBusBridge) handleMessage(_ context.Context, payload string) {
	if len(payload) == 0 {
		return
	}

	var bm bridgeMessage
	if err := json.Unmarshal([]byte(payload), &bm); err != nil {
		b.l.Error("failed to unmarshal bridge message: ", err)

		return
	}

	if bm.Client == b.id {
		return
	}

	evt.Bus().Publish(evt.BlockingStateChangedRemote, bm.State)
}
