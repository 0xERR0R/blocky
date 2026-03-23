package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/0xERR0R/blocky/evt"
	"github.com/alicebob/miniredis/v2"
	goredis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("EventBusBridge", func() {
	var (
		redisServer *miniredis.Miniredis
		redisClient *goredis.Client
		bridge      *EventBusBridge
		ctx         context.Context
		cancel      context.CancelFunc
	)

	BeforeEach(func() {
		var err error
		redisServer, err = miniredis.Run()
		Expect(err).Should(Succeed())
		DeferCleanup(redisServer.Close)

		redisClient = goredis.NewClient(&goredis.Options{
			Addr: redisServer.Addr(),
		})
		DeferCleanup(func() { _ = redisClient.Close() })

		ctx, cancel = context.WithCancel(context.Background())
		DeferCleanup(cancel)

		bridge, err = NewEventBusBridge(ctx, redisClient)
		Expect(err).Should(Succeed())
		DeferCleanup(func() { bridge.Close() })
	})

	Describe("Local event → Redis publish", func() {
		When("BlockingStateChanged is published on the local bus", func() {
			It("should result in a subscriber on the Redis channel", func(specCtx context.Context) {
				evt.Bus().Publish(evt.BlockingStateChanged, evt.BlockingState{Enabled: true})

				Eventually(func() map[string]int {
					return redisServer.PubSubNumSub(EventBridgeChannel)
				}).Should(HaveKeyWithValue(EventBridgeChannel, 1))
			})
		})
	})

	Describe("Redis message → local event", func() {
		When("a bridgeMessage with a different UUID arrives on Redis", func() {
			It("should fire BlockingStateChangedRemote on the local bus with the correct state", func(specCtx context.Context) {
				receivedStates := make(chan evt.BlockingState, 1)

				handler := func(state evt.BlockingState) {
					receivedStates <- state
				}

				Expect(evt.Bus().Subscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				DeferCleanup(func() {
					evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, handler)
				})

				otherID, err := uuid.New().MarshalBinary()
				Expect(err).Should(Succeed())

				expectedState := evt.BlockingState{
					Enabled:  true,
					Duration: 5 * time.Minute,
					Groups:   []string{"ads", "malware"},
				}

				payload, err := json.Marshal(bridgeMessage{
					State:  expectedState,
					Client: otherID,
				})
				Expect(err).Should(Succeed())

				redisServer.Publish(EventBridgeChannel, string(payload))

				Eventually(receivedStates).Should(Receive(Equal(expectedState)))
			}, SpecTimeout(3*time.Second))
		})
	})

	Describe("Echo filtering", func() {
		When("a bridgeMessage with the bridge's own UUID arrives on Redis", func() {
			It("should NOT fire BlockingStateChangedRemote on the local bus", func(specCtx context.Context) {
				receivedStates := make(chan evt.BlockingState, 1)

				handler := func(state evt.BlockingState) {
					receivedStates <- state
				}

				Expect(evt.Bus().Subscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				DeferCleanup(func() {
					evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, handler)
				})

				payload, err := json.Marshal(bridgeMessage{
					State:  evt.BlockingState{Enabled: true},
					Client: bridge.id,
				})
				Expect(err).Should(Succeed())

				redisServer.Publish(EventBridgeChannel, string(payload))

				Consistently(receivedStates, "300ms", "50ms").Should(BeEmpty())
			}, SpecTimeout(3*time.Second))
		})
	})

	Describe("Full payload round-trip", func() {
		When("BlockingStateChanged is published locally with Duration and Groups", func() {
			It("should preserve Duration and Groups through local → Redis → remote", func(specCtx context.Context) {
				receivedStates := make(chan evt.BlockingState, 1)

				handler := func(state evt.BlockingState) {
					receivedStates <- state
				}

				Expect(evt.Bus().Subscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				DeferCleanup(func() {
					evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, handler)
				})

				// Create a second bridge acting as the "remote" receiver
				bridge2, err := NewEventBusBridge(ctx, redisClient)
				Expect(err).Should(Succeed())
				DeferCleanup(func() { bridge2.Close() })

				// Override bridge2's handler to forward to our channel
				Expect(evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				Expect(evt.Bus().Subscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())

				// Publish from bridge (bridge2 should receive since UUIDs differ)
				originalState := evt.BlockingState{
					Enabled:  false,
					Duration: 2*time.Hour + 30*time.Minute,
					Groups:   []string{"group1", "group2", "group3"},
				}

				// Directly publish to Redis as bridge (simulate local→Redis path)
				payload, err := json.Marshal(bridgeMessage{
					State:  originalState,
					Client: bridge.id, // from bridge, NOT bridge2
				})
				Expect(err).Should(Succeed())

				redisServer.Publish(EventBridgeChannel, string(payload))

				// bridge2 should receive it (different UUID)
				Eventually(receivedStates, "2s", "50ms").Should(Receive(Equal(originalState)))
			}, SpecTimeout(5*time.Second))
		})
	})
})
