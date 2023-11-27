package util

import "context"

// CtxSend sends a value to a channel while the context isn't done.
// If the message is sent, it returns true.
// If the context is done or the channel is closed, it returns false.
func CtxSend[T any](ctx context.Context, ch chan T, val T) (ok bool) {
	if ctx == nil || ch == nil || ctx.Err() != nil {
		ok = false

		return
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

	return
}
