package util

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	testMessage = 1
)

var _ = Describe("Context utils", func() {
	Describe("CtxSend", func() {
		var ch chan int
		BeforeEach(func() {
			ch = make(chan int, 1)
		})

		AfterEach(func() {
			ch = nil
		})

		When("channel is not closed", func() {
			It("should send value to channel", func(ctx context.Context) {
				go startReader(ctx, ch)
				Expect(CtxSend(ctx, ch, testMessage)).Should(BeTrue())
			}, SpecTimeout(time.Second))
		})

		When("channel is closed", func() {
			It("should return false", func(ctx context.Context) {
				go startReader(ctx, ch)
				close(ch)
				Expect(CtxSend(ctx, ch, testMessage)).Should(BeFalse())
			}, SpecTimeout(time.Second))
		})

		When("channel is nil", func() {
			It("should return false", func(ctx context.Context) {
				Expect(CtxSend(ctx, nil, testMessage)).Should(BeFalse())
			}, SpecTimeout(time.Second))
		})

		When("channel is full", func() {
			It("should wait", func(ctx context.Context) {
				ch <- testMessage
				go func(ctx context.Context, ch chan int) {
					timer := time.NewTimer(time.Millisecond * 200)
					select {
					case <-timer.C:
						startReader(ctx, ch)
					case <-ctx.Done():
						return
					}
				}(ctx, ch)
				Expect(CtxSend(ctx, ch, testMessage)).Should(BeTrue())
			}, SpecTimeout(time.Second))
		})

		When("context is done", func() {
			It("should return false", func(ctx context.Context) {
				go startReader(ctx, ch)
				cCtx, cancel := context.WithCancel(ctx)
				cancel()
				<-cCtx.Done()
				Expect(CtxSend(cCtx, ch, testMessage)).Should(BeFalse())
			}, SpecTimeout(time.Second))
		})

		When("context is terminated", func() {
			It("should return false", func(ctx context.Context) {
				ch <- testMessage
				cCtx, cancel := context.WithCancel(ctx)
				go func(ctx context.Context, cancel context.CancelFunc) {
					timer := time.NewTimer(time.Millisecond * 200)
					select {
					case <-timer.C:
						cancel()
					case <-ctx.Done():
						return
					}
				}(ctx, cancel)
				Expect(CtxSend(cCtx, ch, testMessage)).Should(BeFalse())
			}, SpecTimeout(time.Second))
		})

		When("context is nil", func() {
			It("should return false", func(ctx context.Context) {
				Expect(CtxSend(nil, ch, testMessage)).Should(BeFalse())
			}, SpecTimeout(time.Second))
		})

		When("context and channel are nil", func() {
			It("should return false", func(ctx context.Context) {
				Expect(CtxSend(nil, nil, testMessage)).Should(BeFalse())
			}, SpecTimeout(time.Second))
		})

		When("context is done and channel is closed", func() {
			It("should return false", func(ctx context.Context) {
				go startReader(ctx, ch)
				ctx, cancel := context.WithCancel(ctx)
				cancel()
				close(ch)
				Expect(CtxSend(ctx, ch, testMessage)).Should(BeFalse())
			}, SpecTimeout(time.Second))
		})
	})
})

func startReader(ctx context.Context, ch <-chan int) {
	for {
		select {
		case <-ctx.Done():
			return
		case i, ok := <-ch:
			if ok {
				Expect(i).Should(Equal(testMessage))
			}
		}
	}
}
