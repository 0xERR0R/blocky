package redis

import (
	"context"
	"time"

	goredis "github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

const (
	reconnectBaseDelay = 500 * time.Millisecond
	reconnectMaxDelay  = 30 * time.Second
)

// PubSubLoop manages a Redis pub/sub subscription with automatic reconnection.
// It calls handler for each received message payload and reconnects with
// exponential backoff when the channel closes unexpectedly.
type PubSubLoop struct {
	Client  *goredis.Client
	Channel string
	Logger  *logrus.Entry
	Handler func(ctx context.Context, payload string)
}

// Run subscribes to the channel and processes messages until ctx is cancelled.
// It reconnects automatically on unexpected channel closure.
func (p *PubSubLoop) Run(ctx context.Context) {
	p.RunWithSub(ctx, nil)
}

// RunWithSub is like Run but uses an existing subscription for the first iteration.
// If initial is nil, a new subscription is created.
func (p *PubSubLoop) RunWithSub(ctx context.Context, initial *goredis.PubSub) {
	sub := initial
	if sub == nil {
		var err error

		sub, err = p.subscribe(ctx)
		if err != nil {
			p.Logger.WithError(err).Warn("Redis pub/sub initial subscribe failed, attempting to reconnect")

			sub = p.reconnect(ctx)
			if sub == nil {
				return
			}
		}
	}

	for {
		p.consume(ctx, sub)
		_ = sub.Close()

		if ctx.Err() != nil {
			return
		}

		p.Logger.Warn("Redis pub/sub channel closed unexpectedly, attempting to reconnect")

		sub = p.reconnect(ctx)
		if sub == nil {
			return
		}
	}
}

func (p *PubSubLoop) consume(ctx context.Context, sub *goredis.PubSub) {
	ch := sub.Channel()

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}

			if msg == nil {
				continue
			}

			p.Handler(ctx, msg.Payload)

		case <-ctx.Done():
			return
		}
	}
}

// reconnect attempts to re-subscribe with exponential backoff.
// Returns nil if the context is cancelled before reconnecting.
func (p *PubSubLoop) reconnect(ctx context.Context) *goredis.PubSub {
	delay := reconnectBaseDelay

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}

		sub, err := p.subscribe(ctx)
		if err != nil {
			p.Logger.WithError(err).Warn("Redis pub/sub reconnect failed, retrying")

			delay *= 2
			if delay > reconnectMaxDelay {
				delay = reconnectMaxDelay
			}

			continue
		}

		p.Logger.Info("Redis pub/sub reconnected successfully")

		return sub
	}
}

// subscribe closes the subscription on cancellation because Receive ignores
// context cancellation while waiting for Redis.
func (p *PubSubLoop) subscribe(ctx context.Context) (*goredis.PubSub, error) {
	sub := p.Client.Subscribe(ctx, p.Channel)
	stop := context.AfterFunc(ctx, func() { _ = sub.Close() })
	defer stop()

	if _, err := sub.Receive(ctx); err != nil {
		_ = sub.Close()

		return nil, err
	}

	return sub, nil
}
