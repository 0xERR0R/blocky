package util

import (
	"unsafe"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("GrowStack", func() {
	It("grows the stack of the calling goroutine", func() {
		moved := make(chan bool)

		// A new goroutine starts with a stack too small for the frame, and the runtime
		// grows a stack by moving it: a variable on the stack gets another address.
		go func() {
			// stays on the stack: its address leaves the goroutine only as a number
			var onStack byte

			before := uintptr(unsafe.Pointer(&onStack))

			GrowStack[[64 << 10]byte]()

			moved <- uintptr(unsafe.Pointer(&onStack)) != before
		}()

		Expect(<-moved).Should(BeTrue())
	})
})
