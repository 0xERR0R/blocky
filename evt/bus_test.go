package evt_test

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/evt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type (
	fooEvent struct{ N int }
	barEvent struct{ S string }
)

var _ = Describe("Bus", func() {
	var bus *evt.Bus

	BeforeEach(func() {
		bus = evt.NewBus()
	})

	Describe("Emit", func() {
		When("there are no listeners", func() {
			It("is a no-op", func() {
				Expect(func() {
					evt.Emit(bus, context.Background(), fooEvent{N: 1})
				}).ShouldNot(Panic())
			})
		})

		When("the bus is nil", func() {
			It("is a no-op (Bootstrap silence contract)", func() {
				Expect(func() {
					evt.Emit[fooEvent](nil, context.Background(), fooEvent{N: 1})
				}).ShouldNot(Panic())
			})
		})

		When("a listener is registered for the event type", func() {
			It("delivers the event payload to the listener", func(specCtx context.Context) {
				received := make(chan fooEvent, 1)
				evt.Subscribe(bus, "k", func(_ context.Context, e fooEvent) {
					received <- e
				})

				evt.Emit(bus, specCtx, fooEvent{N: 42})

				Eventually(received).WithTimeout(time.Second).Should(Receive(Equal(fooEvent{N: 42})))
			})
		})

		When("multiple listeners are registered for the same event type", func() {
			It("delivers the event to every listener", func(specCtx context.Context) {
				var count atomic.Int32
				var wg sync.WaitGroup
				wg.Add(2)

				evt.Subscribe(bus, "a", func(_ context.Context, _ fooEvent) {
					count.Add(1)
					wg.Done()
				})
				evt.Subscribe(bus, "b", func(_ context.Context, _ fooEvent) {
					count.Add(1)
					wg.Done()
				})

				evt.Emit(bus, specCtx, fooEvent{})

				done := make(chan struct{})
				go func() { wg.Wait(); close(done) }()
				Eventually(done).WithTimeout(time.Second).Should(BeClosed())
				Expect(count.Load()).To(Equal(int32(2)))
			})
		})

		When("listeners are registered for different event types", func() {
			It("delivers to only the matching type", func(specCtx context.Context) {
				received := make(chan fooEvent, 1)
				var barCalls atomic.Int32

				evt.Subscribe(bus, "foo", func(_ context.Context, e fooEvent) {
					received <- e
				})
				evt.Subscribe(bus, "bar", func(_ context.Context, _ barEvent) {
					barCalls.Add(1)
				})

				evt.Emit(bus, specCtx, fooEvent{N: 7})

				Eventually(received).WithTimeout(time.Second).Should(Receive(Equal(fooEvent{N: 7})))
				Consistently(barCalls.Load, 100*time.Millisecond).Should(Equal(int32(0)))
			})
		})
	})

	Describe("EmitAsync", func() {
		When("the bus is nil", func() {
			It("is a no-op", func() {
				Expect(func() {
					evt.EmitAsync[fooEvent](nil, context.Background(), fooEvent{N: 1})
				}).ShouldNot(Panic())
			})
		})

		When("a listener is registered", func() {
			It("delivers the event eventually", func(specCtx context.Context) {
				received := make(chan fooEvent, 1)
				evt.Subscribe(bus, "k", func(_ context.Context, e fooEvent) {
					received <- e
				})

				evt.EmitAsync(bus, specCtx, fooEvent{N: 99})

				Eventually(received).WithTimeout(time.Second).Should(Receive(Equal(fooEvent{N: 99})))
			})
		})

		When("a listener blocks", func() {
			It("returns to the caller without waiting for the listener", func(specCtx context.Context) {
				release := make(chan struct{})
				started := make(chan struct{}, 1)
				evt.Subscribe(bus, "slow", func(_ context.Context, _ fooEvent) {
					started <- struct{}{}
					<-release // block until the test releases us
				})
				DeferCleanup(func() { close(release) })

				returned := make(chan struct{})
				go func() {
					evt.EmitAsync(bus, specCtx, fooEvent{})
					close(returned)
				}()

				// EmitAsync must return promptly even though the listener is still blocked.
				Eventually(returned).WithTimeout(time.Second).Should(BeClosed())
				Eventually(started).WithTimeout(time.Second).Should(Receive())
			})
		})
	})

	Describe("Subscribe with nil bus", func() {
		It("is a no-op for Subscribe and Unsubscribe", func() {
			Expect(func() {
				evt.Subscribe[fooEvent](nil, "k", func(context.Context, fooEvent) {})
				evt.Unsubscribe[fooEvent](nil, "k")
			}).ShouldNot(Panic())
		})
	})

	Describe("Unsubscribe", func() {
		It("stops delivery to a listener identified by key", func(specCtx context.Context) {
			var count atomic.Int32
			received := make(chan struct{}, 1)

			evt.Subscribe(bus, "to-remove", func(_ context.Context, _ fooEvent) {
				count.Add(1)
				received <- struct{}{}
			})

			evt.Emit(bus, specCtx, fooEvent{})
			Eventually(received).WithTimeout(time.Second).Should(Receive())

			evt.Unsubscribe[fooEvent](bus, "to-remove")
			evt.Emit(bus, specCtx, fooEvent{})

			Consistently(count.Load, 100*time.Millisecond).Should(Equal(int32(1)))
		})
	})

	Describe("Concurrent emit and subscribe", func() {
		It("does not race or panic", func(specCtx context.Context) {
			const goroutines = 16
			const perGoroutine = 100
			var wg sync.WaitGroup

			for i := 0; i < goroutines; i++ {
				wg.Add(1)
				go func(i int) {
					defer GinkgoRecover()
					defer wg.Done()
					evt.Subscribe(bus, "k", func(_ context.Context, _ fooEvent) {})
					for j := 0; j < perGoroutine; j++ {
						evt.Emit(bus, specCtx, fooEvent{N: i*perGoroutine + j})
					}
				}(i)
			}
			wg.Wait()
		})
	})
})
