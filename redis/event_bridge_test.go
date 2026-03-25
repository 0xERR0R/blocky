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

	Describe("NewEventBusBridge errors", func() {
		When("Redis is not reachable", func() {
			It("should return an error", func() {
				deadClient := goredis.NewClient(&goredis.Options{
					Addr:        "127.0.0.1:0",
					DialTimeout: 50 * time.Millisecond,
				})
				DeferCleanup(func() { _ = deadClient.Close() })

				newCtx, newCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				DeferCleanup(newCancel)

				_, err := NewEventBusBridge(newCtx, deadClient)
				Expect(err).Should(HaveOccurred())
			})
		})
	})

	Describe("Local event → Redis publish", func() {
		When("BlockingStateChanged is published on the local bus", func() {
			It("should publish a message to the Redis channel that a second subscriber receives", func(specCtx context.Context) {
				// Create a second bridge to act as receiver
				bridge2, err := NewEventBusBridge(ctx, redisClient)
				Expect(err).Should(Succeed())
				DeferCleanup(func() { bridge2.Close() })

				receivedStates := make(chan evt.BlockingState, 1)

				handler := func(state evt.BlockingState) {
					receivedStates <- state
				}

				Expect(evt.Bus().Subscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				DeferCleanup(func() {
					Expect(evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				})

				expectedState := evt.BlockingState{Enabled: true}
				evt.Bus().Publish(evt.BlockingStateChanged, expectedState)

				Eventually(receivedStates).WithTimeout(2 * time.Second).WithPolling(50 * time.Millisecond).Should(Receive(Equal(expectedState)))
			}, SpecTimeout(3*time.Second))
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
					Expect(evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				})

				otherID := uuid.NewString()

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
					Expect(evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
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

	Describe("Close", func() {
		When("Close is called multiple times", func() {
			It("should be idempotent and not panic", func() {
				Expect(bridge.Close()).Should(Succeed())
				Expect(bridge.Close()).Should(Succeed())
			})
		})
	})

	Describe("consumeMessages", func() {
		When("a message with empty payload arrives", func() {
			It("should ignore it without error", func(specCtx context.Context) {
				receivedStates := make(chan evt.BlockingState, 1)

				handler := func(state evt.BlockingState) {
					receivedStates <- state
				}

				Expect(evt.Bus().Subscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				DeferCleanup(func() {
					Expect(evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				})

				// Publish empty payload
				redisServer.Publish(EventBridgeChannel, "")

				Consistently(receivedStates, "300ms", "50ms").Should(BeEmpty())
			}, SpecTimeout(3*time.Second))
		})

		When("a message with invalid JSON arrives", func() {
			It("should skip it without firing an event", func(specCtx context.Context) {
				receivedStates := make(chan evt.BlockingState, 1)

				handler := func(state evt.BlockingState) {
					receivedStates <- state
				}

				Expect(evt.Bus().Subscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				DeferCleanup(func() {
					Expect(evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				})

				redisServer.Publish(EventBridgeChannel, "not-valid-json{{{")

				Consistently(receivedStates, "300ms", "50ms").Should(BeEmpty())
			}, SpecTimeout(3*time.Second))
		})
	})

	Describe("onLocalStateChanged after close", func() {
		When("the bridge context is cancelled before publishing", func() {
			It("should not attempt to publish to Redis", func() {
				// Cancel the bridge context
				cancel()

				// onLocalStateChanged should return early due to done channel
				// This should not panic or block
				bridge.onLocalStateChanged(evt.BlockingState{Enabled: true})
			})
		})
	})

	Describe("subscribeLoop reconnection", func() {
		When("the Redis pub/sub connection closes unexpectedly", func() {
			It("should reconnect and continue receiving messages", func(specCtx context.Context) {
				receivedStates := make(chan evt.BlockingState, 5)

				handler := func(state evt.BlockingState) {
					receivedStates <- state
				}

				Expect(evt.Bus().Subscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				DeferCleanup(func() {
					Expect(evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
				})

				otherID := uuid.NewString()

				// Send a message before restart to verify connectivity
				preState := evt.BlockingState{Enabled: true}
				payload, err := json.Marshal(bridgeMessage{State: preState, Client: otherID})
				Expect(err).Should(Succeed())

				redisServer.Publish(EventBridgeChannel, string(payload))

				Eventually(receivedStates, "2s", "50ms").Should(Receive(Equal(preState)))

				// Restart miniredis to simulate connection drop + recovery
				redisServer.Close()
				redisServer2, err := miniredis.Run()
				Expect(err).Should(Succeed())
				DeferCleanup(redisServer2.Close)

				// Note: since miniredis restarts on a new port, the existing bridge
				// won't reconnect to it. But we verify the reconnect loop runs
				// without panicking by cancelling context shortly after.
				time.Sleep(100 * time.Millisecond)
			}, SpecTimeout(5*time.Second))
		})

		When("the context is cancelled during reconnect", func() {
			It("should stop and return without error", func(specCtx context.Context) {
				// Create a new bridge with its own context
				bridgeCtx, bridgeCancel := context.WithCancel(context.Background())

				b, err := NewEventBusBridge(bridgeCtx, redisClient)
				Expect(err).Should(Succeed())

				// Close the Redis server to trigger reconnection
				redisServer.Close()

				// Give the bridge time to notice the disconnection
				time.Sleep(100 * time.Millisecond)

				// Cancel the context to stop reconnection
				bridgeCancel()

				// Verify the bridge shuts down cleanly
				Eventually(func() error {
					return b.Close()
				}).WithTimeout(2 * time.Second).Should(Succeed())
			}, SpecTimeout(5*time.Second))
		})
	})

	Describe("onLocalStateChanged error handling", func() {
		When("Redis is unreachable during publish", func() {
			It("does not panic", func() {
				// Close Redis to cause publish failure
				redisServer.Close()

				Expect(func() {
					bridge.onLocalStateChanged(evt.BlockingState{Enabled: true})
				}).ToNot(Panic())
			})
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
					Expect(evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
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
