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
	mu          sync.RWMutex
	subscribers map[*subscriber]struct{}
	ring        *RingBuffer[LogEntry]
	ctx         context.Context
}

func NewBroadcaster(ctx context.Context, ringSize int) *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[*subscriber]struct{}),
		ring:        NewRingBuffer[LogEntry](ringSize),
		ctx:         ctx,
	}
}

// Publish sends an entry to all subscribers and stores it in the ring buffer.
// Slow subscribers whose channel is full are evicted.
func (b *Broadcaster) Publish(entry LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.ring.Add(entry)

	for sub := range b.subscribers {
		select {
		case sub.ch <- entry:
		default:
			// Slow client — evict
			close(sub.ch)
			delete(b.subscribers, sub)
		}
	}
}

// Subscribe returns a channel of log entries and a cancel function.
// The channel receives backfill from the ring buffer, then live entries.
func (b *Broadcaster) Subscribe() (<-chan LogEntry, func()) {
	ch := make(chan LogEntry, subscriberBufSize)

	b.mu.Lock()

	// Backfill from ring buffer
	for _, entry := range b.ring.Entries() {
		ch <- entry
	}

	sub := &subscriber{ch: ch}
	sub.cancel = func() {
		b.mu.Lock()
		defer b.mu.Unlock()

		if _, ok := b.subscribers[sub]; ok {
			close(sub.ch)
			delete(b.subscribers, sub)
		}
	}

	b.subscribers[sub] = struct{}{}
	b.mu.Unlock()

	return ch, sub.cancel
}

// Shutdown closes all subscriber channels.
func (b *Broadcaster) Shutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()

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

// Entries returns buffered items in chronological order.
func (r *RingBuffer[T]) Entries() []T {
	if !r.full {
		return r.buf[:r.pos]
	}

	result := make([]T, len(r.buf))
	copy(result, r.buf[r.pos:])
	copy(result[len(r.buf)-r.pos:], r.buf[:r.pos])

	return result
}
