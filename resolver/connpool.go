package resolver

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// connPool is an io.Closer; Close releases all idle connections.
var _ io.Closer = (*connPool)(nil)

// pooledConn is an idle connection waiting in the pool together with the time it
// was last returned, used to enforce the idle TTL.
type pooledConn struct {
	conn     *dns.Conn
	returned time.Time
}

// connPool is a per-address pool of persistent DNS connections for a single
// upstream client (currently DoT). It removes the TCP + TLS handshake from every
// cache miss by reusing connections, while staying safe against stale
// (server-closed) connections and never growing without bound.
//
// Safety properties:
//   - maxIdle caps the number of idle connections kept per address; surplus
//     connections are closed on return, so a burst can't leak file descriptors.
//   - idleTTL bounds how long a connection may sit idle; acquire evicts every
//     connection idle longer than the TTL (oldest first), before a server is
//     likely to have closed them.
//   - exchange retries once on a fresh connection when a pooled connection turns
//     out to be stale (a server-closed connection can't be detected up front),
//     so reuse never surfaces a spurious error to the caller.
type connPool struct {
	client  *dns.Client
	maxIdle int
	idleTTL time.Duration

	// now is overridable in tests; defaults to time.Now.
	now func() time.Time

	mu   sync.Mutex
	idle map[string][]pooledConn

	dialed      atomic.Int64
	reused      atomic.Int64
	closedStale atomic.Int64
	retried     atomic.Int64
}

// connPoolStats is a snapshot of the pool's lifetime counters, used by metrics
// and tests to confirm reuse and the absence of leaks.
type connPoolStats struct {
	dialed      int64
	reused      int64
	closedStale int64
	retried     int64
}

func newConnPool(client *dns.Client, maxIdle int, idleTTL time.Duration) *connPool {
	return &connPool{
		client:  client,
		maxIdle: maxIdle,
		idleTTL: idleTTL,
		now:     time.Now,
		idle:    make(map[string][]pooledConn),
	}
}

func (p *connPool) stats() connPoolStats {
	return connPoolStats{
		dialed:      p.dialed.Load(),
		reused:      p.reused.Load(),
		closedStale: p.closedStale.Load(),
		retried:     p.retried.Load(),
	}
}

// idleCount returns the total number of idle connections currently pooled.
func (p *connPool) idleCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	var n int
	for _, conns := range p.idle {
		n += len(conns)
	}

	return n
}

// acquire returns a healthy pooled connection for addr (most-recently-returned
// first), or nil if none is available. Connections idle longer than idleTTL are
// closed and skipped.
func (p *connPool) acquire(addr string) *dns.Conn {
	var (
		found *dns.Conn
		stale []*dns.Conn
	)

	now := p.now()

	p.mu.Lock()
	conns := p.idle[addr]

	// Connections are appended in return order, so `returned` increases with the
	// index and the TTL-expired connections are always a leading prefix. Evict
	// the whole prefix, even when a healthy connection is available to return, so
	// older idle connections are reaped instead of lingering under steady traffic.
	expired := 0
	for expired < len(conns) && now.Sub(conns[expired].returned) > p.idleTTL {
		stale = append(stale, conns[expired].conn)
		expired++
	}

	conns = conns[expired:]

	// Reuse the most-recently-returned remaining connection.
	if len(conns) > 0 {
		last := len(conns) - 1
		found = conns[last].conn
		conns = conns[:last]
	}

	p.idle[addr] = conns
	p.mu.Unlock()

	// Close stale connections outside the lock: tls.Conn.Close writes a
	// close_notify alert and can block, which would serialize the whole pool.
	for _, conn := range stale {
		_ = conn.Close()
		p.closedStale.Add(1)
	}

	return found
}

// putBack returns conn to the pool for addr, or closes it if the pool is full.
func (p *connPool) putBack(addr string, conn *dns.Conn) {
	p.mu.Lock()

	if len(p.idle[addr]) >= p.maxIdle {
		p.mu.Unlock()

		// Close outside the lock; see acquire.
		_ = conn.Close()

		return
	}

	p.idle[addr] = append(p.idle[addr], pooledConn{conn: conn, returned: p.now()})
	p.mu.Unlock()
}

// dial opens a new connection to addr and counts it.
func (p *connPool) dial(ctx context.Context, addr string) (*dns.Conn, error) {
	conn, err := p.client.DialContext(ctx, addr)
	if err != nil {
		return nil, err
	}

	p.dialed.Add(1)

	return conn, nil
}

// exchange sends msg to addr, reusing a pooled connection when possible. A stale
// pooled connection is transparently replaced by a single fresh dial, so callers
// never see an error caused purely by connection reuse.
func (p *connPool) exchange(
	ctx context.Context, msg *dns.Msg, addr string,
) (resp *dns.Msg, rtt time.Duration, err error) {
	if conn := p.acquire(addr); conn != nil {
		resp, rtt, err = p.client.ExchangeWithConnContext(ctx, msg, conn)
		if err == nil {
			p.reused.Add(1)
			p.putBack(addr, conn)

			return resp, rtt, nil
		}

		// The pooled connection was stale or broke mid-exchange; never reuse it.
		_ = conn.Close()

		// Only a connection-level failure warrants a transparent re-dial. A
		// cancelled/expired context or a timeout (a slow or unresponsive upstream,
		// not a stale connection) is surfaced so the caller's retry and IP
		// rotation handle it instead of silently re-querying the same address.
		if !shouldRedial(ctx, err) {
			return nil, 0, err
		}

		p.retried.Add(1)
	}

	conn, err := p.dial(ctx, addr)
	if err != nil {
		return nil, 0, err
	}

	resp, rtt, err = p.client.ExchangeWithConnContext(ctx, msg, conn)
	if err != nil {
		_ = conn.Close()

		return nil, 0, err
	}

	p.putBack(addr, conn)

	return resp, rtt, nil
}

// shouldRedial reports whether a failed exchange on a pooled connection should
// be retried transparently on a fresh dial. Only connection-level failures (a
// stale pooled connection) qualify; a cancelled/expired context or a timeout is
// surfaced to the caller so its retry and IP-rotation logic can handle it.
func shouldRedial(ctx context.Context, err error) bool {
	return ctx.Err() == nil && !isTimeout(err)
}

// Close closes all idle connections, implementing io.Closer.
func (p *connPool) Close() error {
	// Detach the idle set under the lock, then close outside it: tls.Conn.Close
	// can block writing close_notify, which would serialize concurrent
	// acquire/putBack (see acquire).
	p.mu.Lock()
	idle := p.idle
	p.idle = make(map[string][]pooledConn)
	p.mu.Unlock()

	var errs []error

	for _, conns := range idle {
		for _, pc := range conns {
			if err := pc.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}
