package util

import "context"

// CtxSend sends a value to a channel or returns false if the context is done or the channel is closed.
func CtxSend[T any](ctx context.Context, ch chan T, val T) (ok bool) {
	if ctx == nil || ch == nil {
		return false
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
