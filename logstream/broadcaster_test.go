package logstream_test

import (
	"context"
	"time"

	"github.com/0xERR0R/blocky/logstream"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func entry(msg string) logstream.LogEntry {
	return logstream.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   msg,
	}
}

var _ = Describe("Broadcaster", func() {
	var (
		b      *logstream.Broadcaster
		ctx    context.Context
		cancel context.CancelFunc
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())
		DeferCleanup(cancel)
		b = logstream.NewBroadcaster(ctx, 100)
	})

	It("delivers entries to subscribers", func() {
		ch, unsub := b.Subscribe()
		defer unsub()

		b.Publish(entry("hello"))

		Eventually(ch).Should(Receive(HaveField("Message", "hello")))
	})

	It("delivers to multiple subscribers", func() {
		ch1, unsub1 := b.Subscribe()
		defer unsub1()
		ch2, unsub2 := b.Subscribe()
		defer unsub2()

		b.Publish(entry("multi"))

		Eventually(ch1).Should(Receive(HaveField("Message", "multi")))
		Eventually(ch2).Should(Receive(HaveField("Message", "multi")))
	})

	It("backfills from ring buffer on subscribe", func() {
		b.Publish(entry("old1"))
		b.Publish(entry("old2"))

		ch, unsub := b.Subscribe()
		defer unsub()

		var msgs []string
		for i := 0; i < 2; i++ {
			e := <-ch
			msgs = append(msgs, e.Message)
		}

		Expect(msgs).Should(Equal([]string{"old1", "old2"}))
	})

	It("evicts slow subscribers", func() {
		ch, _ := b.Subscribe()

		// Fill the subscriber buffer (256) + extra to trigger eviction
		for i := 0; i < 300; i++ {
			b.Publish(entry("flood"))
		}

		// Drain buffered entries, then channel should be closed
		for range ch {
			// drain
		}
		// If we get here, the channel was closed (evicted)
	})

	It("shutdown closes all subscriber channels", func() {
		ch, _ := b.Subscribe()

		b.Shutdown()

		Eventually(func() bool {
			_, ok := <-ch
			return ok
		}).Should(BeFalse())
	})

	It("unsubscribe stops delivery", func() {
		ch, unsub := b.Subscribe()
		unsub()

		// Channel should be closed
		Eventually(func() bool {
			_, ok := <-ch
			return ok
		}).Should(BeFalse())
	})
})

var _ = Describe("RingBuffer", func() {
	It("returns entries in order when not full", func() {
		r := logstream.NewRingBuffer[int](5)
		r.Add(1)
		r.Add(2)
		r.Add(3)

		Expect(r.Entries()).Should(Equal([]int{1, 2, 3}))
	})

	It("wraps and returns chronological order when full", func() {
		r := logstream.NewRingBuffer[int](3)
		r.Add(1)
		r.Add(2)
		r.Add(3)
		r.Add(4) // overwrites 1

		Expect(r.Entries()).Should(Equal([]int{2, 3, 4}))
	})

	It("handles exact capacity", func() {
		r := logstream.NewRingBuffer[int](3)
		r.Add(10)
		r.Add(20)
		r.Add(30)

		Expect(r.Entries()).Should(Equal([]int{10, 20, 30}))
	})
})
