package redis

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/alicebob/miniredis/v2"
	miniserver "github.com/alicebob/miniredis/v2/server"
	goredis "github.com/go-redis/redis/v8"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// newSlowCancelClient returns a client whose dials block until cancelled and
// then take a moment to return, so callers can tell whether Close waited.
func newSlowCancelClient() (*goredis.Client, <-chan struct{}, *atomic.Bool) {
	dialStarted := make(chan struct{}, 1)
	dialReturned := new(atomic.Bool)
	client := goredis.NewClient(&goredis.Options{
		Addr:       "127.0.0.1:0",
		MaxRetries: -1,
		Dialer: func(ctx context.Context, _, _ string) (net.Conn, error) {
			select {
			case dialStarted <- struct{}{}:
			default:
			}
			<-ctx.Done()
			time.Sleep(50 * time.Millisecond)
			dialReturned.Store(true)

			return nil, ctx.Err()
		},
	})

	return client, dialStarted, dialReturned
}

var _ = Describe("PubSubLoop", func() {
	It("stops waiting for an unconfirmed subscription when cancelled", func() {
		redisServer, err := miniredis.Run()
		Expect(err).Should(Succeed())
		DeferCleanup(redisServer.Close)
		release := make(chan struct{})
		DeferCleanup(func() { close(release) })
		subscribed := make(chan struct{}, 1)
		redisServer.Server().SetPreHook(func(_ *miniserver.Peer, command string, _ ...string) bool {
			if command != "SUBSCRIBE" {
				return false
			}
			select {
			case subscribed <- struct{}{}:
			default:
			}
			<-release

			return true
		})
		client := goredis.NewClient(&goredis.Options{Addr: redisServer.Addr()})
		DeferCleanup(client.Close)

		ctx, cancel := context.WithCancel(context.Background())
		DeferCleanup(cancel)
		loop := &PubSubLoop{
			Client:  client,
			Channel: "pubsub-test",
			Logger:  log.PrefixedLog("pubsub-test"),
			Handler: func(context.Context, string) {},
		}
		done := make(chan struct{})
		go func() {
			defer close(done)

			loop.Run(ctx)
		}()

		Eventually(subscribed).Should(Receive())
		cancel()
		Eventually(done).Should(BeClosed())
	})
})
