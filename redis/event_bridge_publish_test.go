package redis

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/evt"
	"github.com/alicebob/miniredis/v2"
	goredis "github.com/go-redis/redis/v8"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type bridgePublishHook struct {
	before func(context.Context) error
}

func (h *bridgePublishHook) BeforeProcess(ctx context.Context, cmd goredis.Cmder) (context.Context, error) {
	if cmd.Name() == "publish" {
		return ctx, h.before(ctx)
	}

	return ctx, nil
}

func (*bridgePublishHook) AfterProcess(context.Context, goredis.Cmder) error { return nil }

func (*bridgePublishHook) BeforeProcessPipeline(ctx context.Context, _ []goredis.Cmder) (context.Context, error) {
	return ctx, nil
}

func (*bridgePublishHook) AfterProcessPipeline(context.Context, []goredis.Cmder) error { return nil }

var _ = Describe("EventBusBridge background publication", func() {
	var (
		bridge     *EventBusBridge
		messages   <-chan *goredis.Message
		publishCtx context.Context
		eventDone  chan struct{}
		release    func()
	)

	BeforeEach(func() {
		ctx, cancel := context.WithCancel(context.Background())
		DeferCleanup(cancel)
		redisServer, err := miniredis.Run()
		Expect(err).Should(Succeed())
		DeferCleanup(redisServer.Close)
		redisClient := goredis.NewClient(&goredis.Options{Addr: redisServer.Addr(), MaxRetries: -1})
		DeferCleanup(redisClient.Close)

		entered := make(chan context.Context, 1)
		unblock := make(chan struct{})
		var first atomic.Bool
		var unblockOnce sync.Once
		release = func() { unblockOnce.Do(func() { close(unblock) }) }
		redisClient.AddHook(&bridgePublishHook{before: func(ctx context.Context) error {
			if first.CompareAndSwap(false, true) {
				entered <- ctx
				select {
				case <-unblock:
				case <-ctx.Done():
				}
			}

			return ctx.Err()
		}})
		bridge, err = NewEventBusBridge(ctx, redisClient)
		Expect(err).Should(Succeed())
		DeferCleanup(bridge.Close)
		// Release a stalled publish before cleanup needs the event bus lock.
		DeferCleanup(release)

		subscription := redisClient.Subscribe(ctx, EventBridgeChannel)
		_, err = subscription.Receive(ctx)
		Expect(err).Should(Succeed())
		DeferCleanup(subscription.Close)
		messages = subscription.Channel()
		eventDone = make(chan struct{})
		go func() {
			evt.Bus().Publish(evt.BlockingStateChanged, evt.BlockingState{Enabled: true})
			close(eventDone)
		}()
		Eventually(entered).Should(Receive(&publishCtx))
	})

	receiveState := func() evt.BlockingState {
		GinkgoHelper()
		var message *goredis.Message
		Eventually(messages).Should(Receive(&message))
		var received bridgeMessage
		Expect(json.Unmarshal([]byte(message.Payload), &received)).Should(Succeed())
		Expect(received.Client).Should(Equal(bridge.id))

		return received.State
	}

	It("keeps local and unrelated events responsive while Redis publication is stalled", func() {
		Eventually(eventDone).WithTimeout(200 * time.Millisecond).Should(BeClosed())
		unrelatedDone := make(chan struct{})
		go func() {
			evt.Bus().Publish("redis:responsiveness-test")
			close(unrelatedDone)
		}()
		Eventually(unrelatedDone).WithTimeout(200 * time.Millisecond).Should(BeClosed())
		release()
		Expect(receiveState()).Should(Equal(evt.BlockingState{Enabled: true}))
	})

	It("keeps only the latest pending state and owns its group list", func() {
		Eventually(eventDone).Should(BeClosed())
		for range 100 {
			evt.Bus().Publish(evt.BlockingStateChanged, evt.BlockingState{Groups: []string{"superseded"}})
		}
		latest := evt.BlockingState{Groups: []string{"latest"}}
		evt.Bus().Publish(evt.BlockingStateChanged, latest)
		latest.Groups[0] = "changed by caller"
		Consistently(messages).WithTimeout(100 * time.Millisecond).ShouldNot(Receive())

		release()
		Expect(receiveState()).Should(Equal(evt.BlockingState{Enabled: true}))
		Expect(receiveState()).Should(Equal(evt.BlockingState{Groups: []string{"latest"}}))
		Consistently(messages).WithTimeout(100 * time.Millisecond).ShouldNot(Receive())
	})

	It("subtracts queue waiting time from a timed disable", func() {
		Eventually(eventDone).Should(BeClosed())
		evt.Bus().Publish(evt.BlockingStateChanged, evt.BlockingState{Duration: time.Minute, Groups: []string{"ads"}})
		Consistently(messages).WithTimeout(100 * time.Millisecond).ShouldNot(Receive())

		release()
		Expect(receiveState()).Should(Equal(evt.BlockingState{Enabled: true}))
		state := receiveState()
		Expect(state.Enabled).Should(BeFalse())
		Expect(state.Groups).Should(Equal([]string{"ads"}))
		Expect(state.Duration).Should(BeNumerically(">", 0))
		Expect(state.Duration).Should(BeNumerically("<=", time.Minute-100*time.Millisecond))
	})

	It("does not publish a timed disable that expired while queued", func() {
		Eventually(eventDone).Should(BeClosed())
		evt.Bus().Publish(evt.BlockingStateChanged, evt.BlockingState{Duration: 50 * time.Millisecond})
		Consistently(messages).WithTimeout(100 * time.Millisecond).ShouldNot(Receive())

		release()
		Expect(receiveState()).Should(Equal(evt.BlockingState{Enabled: true}))
		Consistently(messages).WithTimeout(100 * time.Millisecond).ShouldNot(Receive())
	})

	It("cancels in-flight publication and discards pending work on close", func() {
		Eventually(eventDone).Should(BeClosed())
		evt.Bus().Publish(evt.BlockingStateChanged, evt.BlockingState{Groups: []string{"pending"}})
		closed := make(chan struct{})
		go func() {
			_ = bridge.Close()
			close(closed)
		}()
		Eventually(closed).WithTimeout(200 * time.Millisecond).Should(BeClosed())
		Eventually(publishCtx.Done()).Should(BeClosed())
		bridge.onLocalStateChanged(evt.BlockingState{Enabled: true})
		Consistently(messages).WithTimeout(100 * time.Millisecond).ShouldNot(Receive())
	})
})
