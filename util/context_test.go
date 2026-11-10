package util

import (
	"context"
	"errors"
	"sync"
	"testing"
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

var _ = Describe("WithLazyTimeout", func() {
	type key struct{}

	var parent context.Context

	BeforeEach(func() {
		parent = context.WithValue(context.Background(), key{}, "value")
	})

	It("is not done before the timeout", func() {
		ctx, cancel := WithLazyTimeout(parent, time.Hour)
		defer cancel()

		Expect(ctx.Err()).Should(Succeed())
		Expect(ctx.Done()).ShouldNot(BeClosed())
		Expect(ctx.Err()).Should(Succeed())

		deadline, ok := ctx.Deadline()
		Expect(ok).Should(BeTrue())
		Expect(deadline).Should(BeTemporally("~", time.Now().Add(time.Hour), time.Minute))
	})

	It("ends at the timeout", func() {
		ctx, cancel := WithLazyTimeout(parent, 20*time.Millisecond)
		defer cancel()

		Eventually(ctx.Done()).Should(BeClosed())
		Expect(ctx.Err()).Should(MatchError(context.DeadlineExceeded))
	})

	It("reports the timeout when nothing waited for it", func() {
		ctx, cancel := WithLazyTimeout(parent, 20*time.Millisecond)
		defer cancel()

		Eventually(ctx.Err).Should(MatchError(context.DeadlineExceeded))
		Expect(ctx.Done()).Should(BeClosed())
	})

	It("ends when it is canceled", func() {
		ctx, cancel := WithLazyTimeout(parent, time.Hour)
		done := ctx.Done()

		cancel()
		cancel()

		Expect(done).Should(BeClosed())
		Expect(ctx.Err()).Should(MatchError(context.Canceled))
	})

	It("has ended when it is first asked after it was canceled", func() {
		ctx, cancel := WithLazyTimeout(parent, time.Hour)
		cancel()

		Expect(ctx.Err()).Should(MatchError(context.Canceled))
		Expect(ctx.Done()).Should(BeClosed())
		Expect(context.Cause(ctx)).Should(MatchError(context.Canceled))
	})

	It("stays canceled when its parent ends later", func() {
		parent, cancelParent := context.WithCancelCause(parent)
		ctx, cancel := WithLazyTimeout(parent, time.Hour)

		cancel()
		cancelParent(errors.New("parent ended"))

		Expect(ctx.Err()).Should(MatchError(context.Canceled))
		Expect(context.Cause(ctx)).Should(BeIdenticalTo(context.Canceled))
		Expect(ctx.Value(key{})).Should(Equal("value"))
	})

	It("reports the end of its parent when it is canceled later", func() {
		cause := errors.New("parent ended")
		parent, cancelParent := context.WithCancelCause(parent)
		ctx, cancel := WithLazyTimeout(parent, time.Hour)

		cancelParent(cause)
		cancel()

		Expect(ctx.Err()).Should(MatchError(context.Canceled))
		Expect(context.Cause(ctx)).Should(BeIdenticalTo(cause))
	})

	It("stays canceled when its deadline passes later", func() {
		ctx, cancel := WithLazyTimeout(parent, 20*time.Millisecond)
		deadline, _ := ctx.Deadline()

		cancel()

		Eventually(time.Now).Should(BeTemporally(">", deadline))
		Expect(ctx.Err()).Should(MatchError(context.Canceled))
	})

	It("keeps reporting the deadline when it is canceled later", func() {
		ctx, cancel := WithLazyTimeout(parent, -time.Second)

		Expect(ctx.Err()).Should(MatchError(context.DeadlineExceeded))

		cancel()

		Expect(ctx.Err()).Should(MatchError(context.DeadlineExceeded))
	})

	It("ends with its parent", func() {
		parent, cancelParent := context.WithCancel(parent)

		waitedOn, cancel := WithLazyTimeout(parent, time.Hour)
		defer cancel()

		notWaitedOn, cancel := WithLazyTimeout(parent, time.Hour)
		defer cancel()

		done := waitedOn.Done()

		cancelParent()

		Expect(done).Should(BeClosed())
		Expect(waitedOn.Err()).Should(MatchError(context.Canceled))
		Expect(notWaitedOn.Err()).Should(MatchError(context.Canceled))
		Expect(notWaitedOn.Done()).Should(BeClosed())
	})

	It("keeps an earlier deadline of its parent", func() {
		parent, cancelParent := context.WithTimeout(parent, 20*time.Millisecond)
		defer cancelParent()

		ctx, cancel := WithLazyTimeout(parent, time.Hour)
		defer cancel()

		deadline, _ := ctx.Deadline()
		Expect(deadline).Should(BeTemporally("~", time.Now(), time.Minute))
		Eventually(ctx.Err).Should(MatchError(context.DeadlineExceeded))
	})

	It("ends for the reason its parent's earlier deadline gives", func() {
		cause := errors.New("parent timed out")
		parent, cancelParent := context.WithTimeoutCause(parent, 20*time.Millisecond, cause)
		defer cancelParent()

		ctx, cancel := WithLazyTimeout(parent, time.Hour)
		defer cancel()

		Eventually(ctx.Done()).Should(BeClosed())
		Expect(ctx.Err()).Should(MatchError(context.DeadlineExceeded))
		Expect(context.Cause(ctx)).Should(BeIdenticalTo(cause))
	})

	It("ends the contexts derived from it", func() {
		ctx, cancel := WithLazyTimeout(parent, time.Hour)

		derived, cancelDerived := context.WithCancel(context.WithValue(ctx, key{}, "derived"))
		defer cancelDerived()

		Expect(derived.Err()).Should(Succeed())

		cancel()

		Expect(derived.Done()).Should(BeClosed())
		Expect(derived.Err()).Should(MatchError(context.Canceled))
	})

	It("has the values of its parent", func() {
		ctx, cancel := WithLazyTimeout(parent, time.Hour)
		defer cancel()

		Expect(ctx.Value(key{})).Should(Equal("value"))

		// once it is asked, it has them through the context with the timer
		_ = ctx.Done()

		Expect(ctx.Value(key{})).Should(Equal("value"))
	})

	It("sets up nothing until it is asked whether it is done", func() {
		allocs := testing.AllocsPerRun(100, func() {
			ctx, cancel := WithLazyTimeout(parent, time.Hour)
			_ = ctx.Value(key{})

			cancel()
		})

		// the context and its cancel function; context.WithTimeout needs twice as many
		Expect(allocs).Should(BeNumerically("<=", 2))
	})

	It("can be asked and canceled concurrently", func() {
		for range 100 {
			ctx, cancel := WithLazyTimeout(parent, time.Hour)

			var wg sync.WaitGroup

			wg.Go(func() { <-ctx.Done() })
			wg.Go(func() { _ = ctx.Err() })
			wg.Go(func() { _ = ctx.Value(key{}) })
			wg.Go(cancel)

			wg.Wait()

			Expect(ctx.Err()).Should(MatchError(context.Canceled))
		}
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
