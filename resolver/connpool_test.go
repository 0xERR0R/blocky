package resolver

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

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
			It("returns the same connection and counts a reuse", func() {
				conn, _ := newPipeConn()
				pool.putBack(addr, conn)

				Expect(pool.acquire(addr)).Should(BeIdenticalTo(conn))
				Expect(pool.stats().reused).Should(Equal(int64(1)))
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

		When("the pooled connection is already closed", func() {
			It("detects it via the deadline probe and returns nil", func() {
				conn, cc := newPipeConn()
				pool.putBack(addr, conn)

				// Simulate a server-side/idle close that the deadline probe can detect.
				_ = cc.Close()

				Expect(pool.acquire(addr)).Should(BeNil())
				Expect(pool.stats().closedStale).Should(Equal(int64(1)))
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

	Describe("close", func() {
		It("closes every pooled connection and empties the pool", func() {
			c1, cc1 := newPipeConn()
			c2, cc2 := newPipeConn()
			pool.putBack(addr, c1)
			pool.putBack(addr, c2)

			Expect(pool.close()).Should(Succeed())

			Expect(cc1.closes()).Should(Equal(1))
			Expect(cc2.closes()).Should(Equal(1))
			Expect(pool.idleCount()).Should(Equal(0))
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
