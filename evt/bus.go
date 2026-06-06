// Package evt provides a typed event bus on top of github.com/maniartech/signals.
//
// A *Bus is a registry that lazily creates one signals.Signal[T] per event type.
// Producers and consumers use the package-level generic functions Emit, Subscribe,
// and Unsubscribe; the bus itself never grows public fields per event.
//
// All operations are nil-safe: passing a nil bus makes Emit / EmitAsync /
// Subscribe / Unsubscribe no-ops. This is used by resolver.Bootstrap to silence
// its internal CachingResolver.
//
// Emit blocks the caller until every listener returns (listeners run
// concurrently with each other, but not with the caller). Use EmitAsync when
// the producer must not wait on listener latency.
package evt

import (
	"context"
	"reflect"
	"sync"

	"github.com/maniartech/signals"
)

// Bus holds typed signals keyed by event type.
type Bus struct {
	mu      sync.RWMutex
	signals map[reflect.Type]any // value is signals.Signal[T] for the key's element type
}

// NewBus creates an empty Bus.
func NewBus() *Bus {
	return &Bus{signals: make(map[reflect.Type]any)}
}

// Emit publishes an event of type T to all subscribers and blocks until every
// listener returns. Listeners run concurrently with each other but not with the
// caller. A nil bus is a no-op.
func Emit[T any](b *Bus, ctx context.Context, event T) {
	if b == nil {
		return
	}
	signalFor[T](b).Emit(ctx, event)
}

// EmitAsync publishes an event of type T without blocking the caller: dispatch
// to listeners happens in a detached background goroutine and EmitAsync returns
// immediately. Use it when the producer must not wait on listener latency (e.g.
// an emit whose listener performs network I/O). A nil bus is a no-op.
//
// Because dispatch is detached, the caller cannot observe when listeners finish,
// and ordering relative to later Emit/EmitAsync calls is not guaranteed. The
// supplied ctx is captured by the goroutine; if the caller cancels it right
// after the call, listeners observe a cancelled context.
func EmitAsync[T any](b *Bus, ctx context.Context, event T) {
	if b == nil {
		return
	}

	signal := signalFor[T](b)

	go signal.Emit(ctx, event)
}

// Subscribe registers a listener for events of type T under the given key. A
// nil bus is a no-op. The key may later be passed to Unsubscribe to remove
// the listener.
func Subscribe[T any](b *Bus, key string, listener func(context.Context, T)) {
	if b == nil {
		return
	}
	signalFor[T](b).AddListener(listener, key)
}

// Unsubscribe removes a listener for events of type T identified by key. A
// nil bus is a no-op.
func Unsubscribe[T any](b *Bus, key string) {
	if b == nil {
		return
	}
	signalFor[T](b).RemoveListener(key)
}

// signalFor returns the lazily-initialized signal for type T.
func signalFor[T any](b *Bus) signals.Signal[T] {
	typ := reflect.TypeOf((*T)(nil)).Elem()

	b.mu.RLock()
	if s, ok := b.signals[typ]; ok {
		b.mu.RUnlock()
		return s.(signals.Signal[T])
	}
	b.mu.RUnlock()

	b.mu.Lock()
	defer b.mu.Unlock()
	// Double-checked: another goroutine may have created it while we waited.
	if s, ok := b.signals[typ]; ok {
		return s.(signals.Signal[T])
	}
	s := signals.Signal[T](signals.New[T]())
	b.signals[typ] = s
	return s
}
