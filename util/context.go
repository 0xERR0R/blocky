package util

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// CtxSend sends a value to a channel while the context isn't done.
// If the message is sent, it returns true.
// If the context is done or the channel is closed, it returns false.
func CtxSend[T any](ctx context.Context, ch chan T, val T) (ok bool) {
	if ctx == nil || ch == nil || ctx.Err() != nil {
		ok = false

		return ok
	}

	defer func() {
		if err := recover(); err != nil {
			ok = false
		}
	}()

	select {
	case <-ctx.Done():
		ok = false
	case ch <- val:
		ok = true
	}

	return ok
}

// WithLazyTimeout is context.WithTimeout for a context that usually ends before anything
// waits on it, like the context of a query answered from memory.
//
// context.WithTimeout starts a timer and registers with its parent for every context it
// returns. This one does both at the first call of Done.
//
// It reports how it ended as the context of context.WithTimeout does, with one
// exception. Without the timer, the timeout takes effect at the next call of Done or
// Err after it elapsed. If the context is canceled or its parent ends before that call,
// it reports that instead of the deadline.
func WithLazyTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx := &lazyTimeoutCtx{parent: parent, deadline: time.Now().Add(timeout)}

	return ctx, ctx.cancel
}

type lazyTimeoutCtx struct {
	parent   context.Context //nolint:containedctx // a context wraps its parent
	deadline time.Time

	// timed is the context that says how this one ended: parent with the deadline, unless
	// cancel came first. It exists from the first call of Done, of Err once the context
	// ended, or of Value once it was canceled.
	timed atomic.Pointer[timedCtx]
	// mu lets cancel and the start of timed see each other
	mu sync.Mutex
	// canceled reports that cancel was called
	canceled atomic.Bool
}

type timedCtx struct {
	context.Context //nolint:containedctx // the context lazyTimeoutCtx hands its work to

	cancel context.CancelFunc
}

func (c *lazyTimeoutCtx) start() *timedCtx {
	if timed := c.timed.Load(); timed != nil {
		return timed
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if timed := c.timed.Load(); timed != nil {
		return timed
	}

	return c.startLocked()
}

// startLocked sets timed. The caller holds mu.
func (c *lazyTimeoutCtx) startLocked() *timedCtx {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)

	if c.canceled.Load() {
		// cancel ended the context before the parent did: it stays canceled, whatever
		// happened to the parent and the deadline since
		ctx, cancel = context.WithCancel(context.WithoutCancel(c.parent))
		cancel()
	} else {
		ctx, cancel = context.WithDeadline(c.parent, c.deadline)
	}

	timed := &timedCtx{Context: ctx, cancel: cancel}
	c.timed.Store(timed)

	return timed
}

func (c *lazyTimeoutCtx) cancel() {
	c.mu.Lock()
	defer c.mu.Unlock()

	timed := c.timed.Load()
	if timed == nil && !c.canceled.Load() && c.parent.Err() != nil {
		// the parent ended the context first: it reports the end of the parent
		timed = c.startLocked()
	}

	c.canceled.Store(true)

	if timed != nil {
		timed.cancel()
	}
}

// untouched reports that the context has no timed yet and was not canceled.
func (c *lazyTimeoutCtx) untouched() bool {
	return c.timed.Load() == nil && !c.canceled.Load()
}

// ended reports that the parent or the deadline ended the context.
func (c *lazyTimeoutCtx) ended() bool {
	return c.parent.Err() != nil || time.Until(c.deadline) <= 0
}

// Deadline implements `context.Context`.
func (c *lazyTimeoutCtx) Deadline() (time.Time, bool) {
	if earlier, ok := c.parent.Deadline(); ok && earlier.Before(c.deadline) {
		return earlier, true
	}

	return c.deadline, true
}

// Done implements `context.Context`.
func (c *lazyTimeoutCtx) Done() <-chan struct{} {
	return c.start().Done()
}

// Err implements `context.Context`.
func (c *lazyTimeoutCtx) Err() error {
	// nothing ended the context yet: no need for the timer to know
	if c.untouched() && !c.ended() {
		return nil
	}

	return c.start().Err()
}

// Value implements `context.Context`.
func (c *lazyTimeoutCtx) Value(key any) any {
	if c.untouched() {
		return c.parent.Value(key)
	}

	// The context package looks for the context that cancels this one with Value. It
	// must find timed, to cancel the contexts derived from this one without a goroutine
	// for each, and to report why this one ended.
	return c.start().Value(key)
}
