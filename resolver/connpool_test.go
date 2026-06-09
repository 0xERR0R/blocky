package resolver

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// timeoutError is a net.Error reporting a timeout, used to exercise shouldRedial.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return false }

// countingConn wraps a net.Conn and counts how often it is closed, so tests can
// assert that the pool closes connections it discards (no leaks).
type countingConn struct {
	net.Conn

	closeCount atomic.Int32
}

func (c *countingConn) Close() error {
	c.closeCount.Add(1)

	return c.Conn.Close()
}

func (c *countingConn) closes() int {
	return int(c.closeCount.Load())
}

var _ = Describe("connPool", Label("connPool"), func() {
	const addr = "127.0.0.1:853"

	var pool *connPool

	// newPipeConn returns a *dns.Conn backed by an in-memory pipe plus the
	// counting wrapper so the test can observe closes. The far end is closed on
	// cleanup.
	newPipeConn := func() (*dns.Conn, *countingConn) {
		near, far := net.Pipe()
		DeferCleanup(func() { _ = far.Close() })

		cc := &countingConn{Conn: near}

		return &dns.Conn{Conn: cc}, cc
	}

	BeforeEach(func() {
		// client is unused by the acquire/putBack/close unit tests; exchange is
		// covered by the integration tests against the mock DoT server.
		pool = newConnPool(&dns.Client{Net: "tcp-tls"}, 2, time.Minute)
	})

	Describe("acquire", func() {
		When("the pool is empty", func() {
			It("returns nil", func() {
				Expect(pool.acquire(addr)).Should(BeNil())
			})
		})

		When("a healthy connection was put back", func() {
			It("returns the same connection and removes it from the pool", func() {
				conn, _ := newPipeConn()
				pool.putBack(addr, conn)

				Expect(pool.acquire(addr)).Should(BeIdenticalTo(conn))
				Expect(pool.idleCount()).Should(Equal(0))
			})
		})

		When("the pooled connection is older than the idle TTL", func() {
			It("closes it and returns nil", func() {
				now := time.Now()
				pool.now = func() time.Time { return now }

				conn, cc := newPipeConn()
				pool.putBack(addr, conn)

				// Advance the clock beyond the idle TTL.
				pool.now = func() time.Time { return now.Add(time.Minute + time.Second) }

				Expect(pool.acquire(addr)).Should(BeNil())
				Expect(cc.closes()).Should(Equal(1))
				Expect(pool.stats().closedStale).Should(Equal(int64(1)))
			})
		})

		When("an older connection has expired but a newer one is still healthy", func() {
			It("reaps the expired connection and reuses the healthy one", func() {
				base := time.Now()
				pool.now = func() time.Time { return base }

				oldConn, oldCC := newPipeConn()
				pool.putBack(addr, oldConn) // returned at base

				// A newer connection is returned 40s later.
				pool.now = func() time.Time { return base.Add(40 * time.Second) }
				newConn, _ := newPipeConn()
				pool.putBack(addr, newConn)

				// 70s after base: the old conn (70s idle) exceeds the 1m TTL, the
				// newer one (30s idle) does not. The expired one must be reaped even
				// though a healthy connection is available to return.
				pool.now = func() time.Time { return base.Add(70 * time.Second) }

				Expect(pool.acquire(addr)).Should(BeIdenticalTo(newConn))
				Expect(oldCC.closes()).Should(Equal(1))
				Expect(pool.stats().closedStale).Should(Equal(int64(1)))
				Expect(pool.idleCount()).Should(Equal(0))
			})
		})
	})

	Describe("putBack", func() {
		When("the pool is already at maxIdle", func() {
			It("closes the surplus connection instead of leaking it", func() {
				c1, _ := newPipeConn()
				c2, _ := newPipeConn()
				c3, cc3 := newPipeConn()

				pool.putBack(addr, c1)
				pool.putBack(addr, c2)
				pool.putBack(addr, c3) // maxIdle is 2, so this one must be closed

				Expect(pool.idleCount()).Should(Equal(2))
				Expect(cc3.closes()).Should(Equal(1))
			})
		})
	})

	Describe("Close", func() {
		It("closes every pooled connection and empties the pool", func() {
			c1, cc1 := newPipeConn()
			c2, cc2 := newPipeConn()
			pool.putBack(addr, c1)
			pool.putBack(addr, c2)

			Expect(pool.Close()).Should(Succeed())

			Expect(cc1.closes()).Should(Equal(1))
			Expect(cc2.closes()).Should(Equal(1))
			Expect(pool.idleCount()).Should(Equal(0))
		})
	})

	Describe("shouldRedial", func() {
		When("a pooled connection fails with a connection-level error", func() {
			It("re-dials while the context is still live", func() {
				Expect(shouldRedial(context.Background(), errors.New("connection reset by peer"))).
					Should(BeTrue())
			})
		})

		When("the context has been cancelled", func() {
			It("does not re-dial", func() {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				Expect(shouldRedial(ctx, errors.New("connection reset by peer"))).Should(BeFalse())
			})
		})

		When("the failure is a timeout", func() {
			It("does not re-dial, leaving retry/IP-rotation to the caller", func() {
				Expect(shouldRedial(context.Background(), timeoutError{})).Should(BeFalse())
			})
		})
	})

	Describe("concurrency", func() {
		It("is safe under concurrent putBack/acquire", func() {
			const workers = 50

			var wg sync.WaitGroup

			wg.Add(workers)

			for range workers {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()

					// Create the pipe inline: Ginkgo's DeferCleanup (used by
					// newPipeConn) must not be called from spawned goroutines.
					near, far := net.Pipe()
					defer func() { _ = far.Close() }()

					pool.putBack(addr, &dns.Conn{Conn: near})
					_ = pool.acquire(addr)
				}()
			}

			wg.Wait()

			// Whatever the interleaving, the pool must never exceed maxIdle.
			Expect(pool.idleCount()).Should(BeNumerically("<=", 2))
		})
	})
})
