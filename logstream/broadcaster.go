// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package logstream

import (
	"context"
	"sync"
	"time"
)

type LogEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
}

const subscriberBufSize = 256

type subscriber struct {
	ch     chan LogEntry
	cancel func()
}

type Broadcaster struct {
	mu          sync.Mutex
	subscribers map[*subscriber]struct{}
	ring        *RingBuffer[LogEntry]
	ctx         context.Context
	closed      bool
}

func NewBroadcaster(ctx context.Context, ringSize int) *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[*subscriber]struct{}),
		ring:        NewRingBuffer[LogEntry](ringSize),
		ctx:         ctx,
	}
}

// Publish sends an entry to all subscribers and stores it in the ring buffer.
// If the lock is contended (e.g. during subscribe backfill), the entry is dropped.
func (b *Broadcaster) Publish(entry LogEntry) {
	if !b.mu.TryLock() {
		return
	}
	defer b.mu.Unlock()

	b.ring.Add(entry)

	for sub := range b.subscribers {
		select {
		case sub.ch <- entry:
		default:
			close(sub.ch)
			delete(b.subscribers, sub)
		}
	}
}

// Subscribe returns a channel of log entries and a cancel function.
//
// After Shutdown it returns an already-closed channel. Without that, a
// subscriber that arrives in the window between Shutdown and its own Subscribe
// registers against a broadcaster nobody will close again, and the streaming
// handler then blocks on it forever — a leaked goroutine and socket per
// connection that was mid-upgrade when the server stopped. Server.Stop calls
// Shutdown precisely to unblock those handlers, so the window is real.
func (b *Broadcaster) Subscribe() (<-chan LogEntry, func()) {
	ch := make(chan LogEntry, subscriberBufSize)

	b.mu.Lock()

	if b.closed {
		b.mu.Unlock()
		close(ch)

		return ch, func() {}
	}

	backfill := b.ring.Entries()

	sub := &subscriber{ch: ch}
	sub.cancel = sync.OnceFunc(func() {
		b.mu.Lock()
		defer b.mu.Unlock()

		if _, ok := b.subscribers[sub]; ok {
			close(sub.ch)
			delete(b.subscribers, sub)
		}
	})

	b.subscribers[sub] = struct{}{}
	b.mu.Unlock()

	// Backfill outside the lock
	for _, entry := range backfill {
		select {
		case ch <- entry:
		default:
		}
	}

	return ch, sub.cancel
}

// Shutdown closes all subscriber channels, and makes every later Subscribe
// return an already-closed one.
func (b *Broadcaster) Shutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.closed = true

	for sub := range b.subscribers {
		close(sub.ch)
		delete(b.subscribers, sub)
	}
}

// RingBuffer is a fixed-size circular buffer.
type RingBuffer[T any] struct {
	buf  []T
	pos  int
	full bool
}

func NewRingBuffer[T any](size int) *RingBuffer[T] {
	return &RingBuffer[T]{buf: make([]T, size)}
}

func (r *RingBuffer[T]) Add(item T) {
	r.buf[r.pos] = item
	r.pos++

	if r.pos == len(r.buf) {
		r.pos = 0
		r.full = true
	}
}

// Entries returns a copy of buffered items in chronological order.
func (r *RingBuffer[T]) Entries() []T {
	if !r.full {
		result := make([]T, r.pos)
		copy(result, r.buf[:r.pos])

		return result
	}

	result := make([]T, len(r.buf))
	copy(result, r.buf[r.pos:])
	copy(result[len(r.buf)-r.pos:], r.buf[:r.pos])

	return result
}
