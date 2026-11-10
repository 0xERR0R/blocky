package util

import "runtime"

// GrowStack grows the stack of the calling goroutine, unless it is large enough already,
// to hold a call frame of type F: an array such as [8 << 10]byte.
//
// A goroutine starts with a small stack. When a call doesn't fit, the runtime doubles
// the stack: it copies it and adjusts every frame on it, which costs more the deeper the
// goroutine is in its calls. A goroutine known to need a deep stack saves most of that
// work by growing the stack once, while it is still almost empty.
//
// F must not be larger than 64 KiB: the compiler allocates a large variable on the heap,
// which leaves the stack as it is.
//
//go:noinline
func GrowStack[F any]() {
	var frame F

	runtime.KeepAlive(&frame)
}
