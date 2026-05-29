// Package evt provides a typed event bus on top of github.com/maniartech/signals.
//
// A *Bus is a registry that lazily creates one signals.Signal[T] per event type.
// Producers and consumers use the package-level generic functions Emit, Subscribe,
// and Unsubscribe; the bus itself never grows public fields per event.
//
// All operations are nil-safe: passing a nil bus makes Emit / Subscribe /
// Unsubscribe no-ops. This is used by resolver.Bootstrap to silence its
// internal CachingResolver.
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

// Emit publishes an event of type T to all subscribers. A nil bus is a no-op.
func Emit[T any](b *Bus, ctx context.Context, event T) {
	if b == nil {
		return
	}
	signalFor[T](b).Emit(ctx, event)
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
