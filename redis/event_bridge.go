package redis

import (
	"context"
	"encoding/json"
	"slices"
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

type pendingBlockingState struct {
	state     evt.BlockingState
	expiresAt time.Time
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

	pendingMu sync.Mutex
	pending   *pendingBlockingState
	publishCh chan struct{}
}

// EventBusBridgeOptions configures the initial Redis subscription.
type EventBusBridgeOptions struct {
	// BackgroundConnect starts the subscription in the background instead of waiting for Redis.
	BackgroundConnect bool
}

// NewEventBusBridge creates a new EventBusBridge that synchronizes blocking state
// between local event bus and Redis pub/sub, waiting for the initial subscription.
func NewEventBusBridge(ctx context.Context, client *goredis.Client) (*EventBusBridge, error) {
	return NewEventBusBridgeWithOptions(ctx, client, EventBusBridgeOptions{})
}

// NewEventBusBridgeWithOptions creates an EventBusBridge with configurable startup behavior.
func NewEventBusBridgeWithOptions(
	ctx context.Context, client *goredis.Client, opts EventBusBridgeOptions,
) (*EventBusBridge, error) {
	ctx, cancel := context.WithCancel(ctx)

	b := &EventBusBridge{
		client:    client,
		id:        uuid.NewString(),
		channel:   EventBridgeChannel,
		l:         log.PrefixedLog("redis-event-bridge"),
		cancel:    cancel,
		done:      ctx.Done(),
		publishCh: make(chan struct{}, 1),
	}

	if err := evt.Bus().Subscribe(evt.BlockingStateChanged, b.onLocalStateChanged); err != nil {
		cancel()

		return nil, err
	}

	var ps *goredis.PubSub
	if !opts.BackgroundConnect {
		ps = client.Subscribe(ctx, b.channel)
		if _, err := ps.Receive(ctx); err != nil {
			_ = b.Close()
			_ = ps.Close()

			return nil, err
		}
	}

	loop := &PubSubLoop{
		Client:  client,
		Channel: b.channel,
		Logger:  b.l,
		Handler: b.handleMessage,
	}

	go b.runPublisher(ctx)

	go func() {
		defer b.Close()

		loop.RunWithSub(ctx, ps)
	}()

	return b, nil
}

// Close signals both workers to stop and unsubscribes from the local event bus.
// It is safe to call multiple times.
func (b *EventBusBridge) Close() error {
	var unsubErr error

	b.once.Do(func() {
		b.cancel()
		b.pendingMu.Lock()
		b.pending = nil
		b.pendingMu.Unlock()
		unsubErr = evt.Bus().Unsubscribe(evt.BlockingStateChanged, b.onLocalStateChanged)
	})

	return unsubErr
}

// onLocalStateChanged retains the latest state without waiting for Redis.
func (b *EventBusBridge) onLocalStateChanged(state evt.BlockingState) {
	b.pendingMu.Lock()
	defer b.pendingMu.Unlock()

	select {
	case <-b.done:
		return
	default:
	}

	state.Groups = slices.Clone(state.Groups)
	pending := &pendingBlockingState{state: state}
	if !state.Enabled && state.Duration != 0 {
		pending.expiresAt = time.Now().Add(state.Duration)
	}

	// Blocking updates replace the full state, so replaying superseded updates
	// after an outage would only delay the latest requested state.
	b.pending = pending
	select {
	case b.publishCh <- struct{}{}:
	default:
	}
}

func (b *EventBusBridge) runPublisher(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.publishCh:
			b.pendingMu.Lock()
			pending := b.pending
			b.pending = nil
			b.pendingMu.Unlock()

			if pending != nil && ctx.Err() == nil {
				b.publishState(ctx, *pending)
			}
		}
	}
}

func (b *EventBusBridge) publishState(ctx context.Context, pending pendingBlockingState) {
	if !pending.expiresAt.IsZero() {
		pending.state.Duration = time.Until(pending.expiresAt)
		if pending.state.Duration <= 0 {
			// A zero duration means indefinite disabling, not an expired request.
			return
		}
	}

	payload, err := json.Marshal(bridgeMessage{State: pending.state, Client: b.id})
	if err != nil {
		b.l.Error("failed to marshal bridge message: ", err)

		return
	}

	pubCtx, cancel := context.WithTimeout(ctx, bridgePublishTimeout)
	defer cancel()

	if err := b.client.Publish(pubCtx, b.channel, payload).Err(); err != nil && ctx.Err() == nil {
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
