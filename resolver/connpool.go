package resolver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// connPool is an io.Closer; Close closes every connection.
var _ io.Closer = (*connPool)(nil)

var (
	// errConnClosed wraps the cause whenever a pipelined connection is torn down.
	errConnClosed = errors.New("DoT connection closed")

	// errUnpackReply fails the one query whose reply didn't unpack.
	errUnpackReply = errors.New("can't unpack reply")
)

// connPoolMaxAbandoned bounds the IDs a connection keeps reserved for queries
// that stopped waiting. Each is freed when its late reply arrives; only a server
// that drops queries leaves them for good, and past this many the connection is
// replaced to get a fresh ID space.
const connPoolMaxAbandoned = 1024

// connPool pipelines DoT queries over one connection per upstream address
// (RFC 7858 §3.3, RFC 7766 §6.2.1.1), and keeps it to one connection per
// address as RFC 7766 §6.2.2 recommends.
//
// A query takes one of maxInFlight slots on the connection, so a burst waits for
// a slot instead of dialing; this also bounds an address's throughput to about
// maxInFlight per reply latency. Concurrent queries for an address with no live
// connection share one dial.
type connPool struct {
	client      *dns.Client
	maxInFlight int
	idleTTL     time.Duration
	// timeout is the upstream's timeout. It bounds each dial, and decides when a
	// connection stopped responding (see muxConn).
	timeout time.Duration

	// now is overridable in tests; defaults to time.Now. Socket deadlines use
	// the real clock.
	now func() time.Time

	mu    sync.Mutex
	conns map[string]*muxConn
	dials map[string]*dialCall

	dialed  atomic.Int64
	retried atomic.Int64
}

// connPoolStats is a snapshot of the pool's lifetime counters, used by tests.
type connPoolStats struct {
	dialed  int64
	retried int64
}

// dialCall is one in-progress dial, shared by every query waiting on it.
type dialCall struct {
	done chan struct{}
	conn *muxConn
	err  error
}

func newConnPool(client *dns.Client, maxInFlight int, idleTTL, timeout time.Duration) *connPool {
	return &connPool{
		client:      client,
		maxInFlight: maxInFlight,
		idleTTL:     idleTTL,
		timeout:     timeout,
		now:         time.Now,
		conns:       make(map[string]*muxConn),
		dials:       make(map[string]*dialCall),
	}
}

func (p *connPool) stats() connPoolStats {
	return connPoolStats{
		dialed:  p.dialed.Load(),
		retried: p.retried.Load(),
	}
}

// openCount returns the number of connections the pool holds open.
func (p *connPool) openCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.conns)
}

// exchange sends msg to addr over the address's shared connection. A query that
// failed because its connection closed gets one transparent retry on a fresh
// connection; anything else is left to the caller.
func (p *connPool) exchange(
	ctx context.Context, msg *dns.Msg, addr string,
) (*dns.Msg, time.Duration, error) {
	for attempt := 0; ; attempt++ {
		conn, err := p.get(ctx, addr)
		if err != nil {
			return nil, 0, err
		}

		resp, rtt, err := conn.exchange(ctx, msg, p.now)
		if err == nil || attempt > 0 || conn.err() == nil || !shouldRedial(ctx, err) {
			return resp, rtt, err
		}

		p.retried.Add(1)
	}
}

// get returns the address's connection, dialing one if it has none, its
// connection is closed, or it sat idle longer than idleTTL.
func (p *connPool) get(ctx context.Context, addr string) (*muxConn, error) {
	var stale *muxConn

	p.mu.Lock()

	if conn, ok := p.conns[addr]; ok {
		if conn.take(p.now(), p.idleTTL) {
			p.mu.Unlock()

			return conn, nil
		}

		delete(p.conns, addr)
		stale = conn
	}

	call, ok := p.dials[addr]
	if !ok {
		call = &dialCall{done: make(chan struct{})}
		p.dials[addr] = call

		// Not the caller's cancellation: other queries wait on this dial too.
		go p.dial(context.WithoutCancel(ctx), addr, call)
	}

	p.mu.Unlock()

	// Close outside the lock: tls.Conn.Close writes close_notify and can block.
	if stale != nil {
		stale.close(net.ErrClosed)
	}

	select {
	case <-call.done:
		return call.conn, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *connPool) dial(ctx context.Context, addr string, call *dialCall) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	conn, err := p.client.DialContext(ctx, addr)
	if err == nil {
		p.dialed.Add(1)

		call.conn = newMuxConn(conn, p.maxInFlight, p.timeout, p.now)
	}

	call.err = err

	p.mu.Lock()
	delete(p.dials, addr)

	if call.conn != nil {
		p.conns[addr] = call.conn
	}
	p.mu.Unlock()

	close(call.done)
}

// shouldRedial reports whether a failed exchange should be retried on a fresh
// connection. Only connection-level failures qualify; a cancelled or expired
// context or a timeout is surfaced so the caller's retry and IP rotation handle
// it.
func shouldRedial(ctx context.Context, err error) bool {
	return ctx.Err() == nil && !isTimeout(err)
}

// Close closes every connection. A query still waiting on one is retried on a
// new connection, so the pool stays usable.
func (p *connPool) Close() error {
	p.mu.Lock()
	conns := p.conns
	p.conns = make(map[string]*muxConn)
	p.mu.Unlock()

	for _, conn := range conns {
		conn.close(net.ErrClosed)
	}

	return nil
}

// muxConn is one DoT connection carrying many queries at once. Each query is
// written under an ID unique among the connection's in-flight queries (RFC 7766
// §6.2.1), and one reader goroutine hands each reply to the query waiting on its
// ID once its question matches (RFC 7766 §7).
//
// The connection stopped responding when a write doesn't finish within timeout,
// or nothing at all is read for timeout while a written query is unanswered: a
// blackholed path accepts writes and never answers. Either closes it, failing
// the queries still on it with the timeout, which the caller's retry handles.
type muxConn struct {
	conn    *dns.Conn
	slots   chan struct{}
	timeout time.Duration
	done    chan struct{}

	// maxAbandoned is connPoolMaxAbandoned, overridable in tests.
	maxAbandoned int

	writeMu sync.Mutex

	mu      sync.Mutex
	pending map[uint16]*pendingQuery
	// unanswered counts the written queries in pending; the read deadline is set
	// while it is above zero.
	unanswered int
	abandoned  int
	lastUsed   time.Time
	closeErr   error
}

// pendingQuery is a query registered on a muxConn and not yet answered. Its
// reply channel is nil once the caller stopped waiting: the ID stays reserved
// until the late reply arrives, so that reply can't answer a newer query.
type pendingQuery struct {
	query   *dns.Msg
	written bool
	reply   chan reply
}

// reply is what a waiting query receives: the reply, or why it couldn't be read.
type reply struct {
	msg *dns.Msg
	err error
}

func newMuxConn(conn *dns.Conn, maxInFlight int, timeout time.Duration, now func() time.Time) *muxConn {
	c := &muxConn{
		conn:         conn,
		slots:        make(chan struct{}, maxInFlight),
		timeout:      timeout,
		done:         make(chan struct{}),
		maxAbandoned: connPoolMaxAbandoned,
		pending:      make(map[uint16]*pendingQuery),
		lastUsed:     now(),
	}

	go c.readLoop(now)

	return c
}

// exchange writes a copy of msg under a connection-unique ID and waits for its
// reply. The caller's msg is not modified, and its ID is restored in the reply.
func (c *muxConn) exchange(
	ctx context.Context, msg *dns.Msg, now func() time.Time,
) (*dns.Msg, time.Duration, error) {
	select {
	case c.slots <- struct{}{}:
	case <-c.done:
		return nil, 0, c.err()
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}

	defer func() { <-c.slots }()

	query := msg.Copy()
	ch := make(chan reply, 1)

	id, err := c.register(query, ch)
	if err != nil {
		return nil, 0, err
	}

	sent := now()

	if wrote, err := c.write(ctx, id, query); err != nil {
		if !wrote {
			// Nothing reached the wire, so the connection is intact.
			c.unregister(id)

			return nil, 0, err
		}

		c.close(err)

		return nil, 0, c.err()
	}

	resp, err := c.await(ctx, id, ch)
	if err != nil {
		return nil, 0, err
	}

	resp.Id = msg.Id

	return resp, now().Sub(sent), nil
}

// await waits for the query's reply. A reply that arrived together with the
// connection closing or the context ending still counts.
func (c *muxConn) await(ctx context.Context, id uint16, ch chan reply) (*dns.Msg, error) {
	select {
	case r := <-ch:
		return r.msg, r.err
	case <-c.done:
		select {
		case r := <-ch:
			return r.msg, r.err
		default:
			return nil, c.err()
		}
	case <-ctx.Done():
		select {
		case r := <-ch:
			return r.msg, r.err
		default:
		}

		c.abandon(id, ch)

		return nil, ctx.Err()
	}
}

// register reserves an ID that no in-flight query on this connection uses and
// records the query under it.
func (c *muxConn) register(query *dns.Msg, ch chan reply) (uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closeErr != nil {
		return 0, c.closeErr
	}

	// The slots and maxAbandoned keep pending far below the ID space.
	for {
		id := dns.Id()
		if _, taken := c.pending[id]; taken {
			continue
		}

		query.Id = id
		c.pending[id] = &pendingQuery{query: query, reply: ch}

		return id, nil
	}
}

func (c *muxConn) unregister(id uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.pending, id)
}

// write sends the query; wrote reports whether the wire was touched, since only
// then can a failure have left a partial frame.
func (c *muxConn) write(ctx context.Context, id uint16, query *dns.Msg) (wrote bool, err error) {
	packed, err := query.Pack()
	if err != nil {
		return false, err
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// The context may have ended while the query waited for the writer, and no
	// one would read its reply.
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if err := c.expectReply(id); err != nil {
		return true, err
	}

	// Not the query's deadline: a TLS connection whose write timed out can't
	// write again, so the deadline only bounds the write itself.
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return true, err
	}

	_, err = c.conn.Write(packed)

	return true, err
}

// expectReply marks the query written, before its reply can arrive. The first
// written query to go unanswered sets the read deadline.
func (c *muxConn) expectReply(id uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Still pending: deliver only removes written queries.
	c.pending[id].written = true

	c.unanswered++
	if c.unanswered > 1 {
		return nil
	}

	return c.conn.SetReadDeadline(time.Now().Add(c.timeout))
}

// abandon stops waiting for a query. Its ID stays reserved until the late reply
// arrives, and past maxAbandoned the connection is replaced.
func (c *muxConn) abandon(id uint16, ch chan reply) {
	c.mu.Lock()

	// The reply may have been delivered, and its ID reused, since ctx ended.
	if pq, ok := c.pending[id]; ok && pq.reply == ch {
		pq.reply = nil
		c.abandoned++
	}

	tooMany := c.abandoned > c.maxAbandoned

	c.mu.Unlock()

	if tooMany {
		c.close(fmt.Errorf("%d abandoned queries still unanswered", c.maxAbandoned))
	}
}

func (c *muxConn) readLoop(now func() time.Time) {
	for {
		resp, err := c.conn.ReadMsg()
		if resp == nil {
			// An I/O error, a frame too short for a header, or the read deadline:
			// the stream is lost.
			c.close(err)

			return
		}

		r := reply{msg: resp}
		if err != nil {
			// The header unpacked but the rest didn't. The stream is still in sync,
			// so only the query with this ID fails.
			r = reply{err: fmt.Errorf("%w: %w", errUnpackReply, err)}
		}

		if err := c.deliver(resp, r, now()); err != nil {
			c.close(err)

			return
		}
	}
}

// deliver hands r to the query waiting on resp's ID. A reply with an unknown ID
// or a question that doesn't match the query's is dropped. Any frame read shows
// the path is alive, so the read deadline restarts while queries are unanswered.
func (c *muxConn) deliver(resp *dns.Msg, r reply, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastUsed = now

	if pq, ok := c.pending[resp.Id]; ok && pq.written && responseMatchesRequest(pq.query, resp) {
		delete(c.pending, resp.Id)
		c.unanswered--

		if pq.reply == nil {
			c.abandoned--
		} else {
			pq.reply <- r // buffered for exactly this one reply, so it never blocks
		}
	}

	var deadline time.Time
	if c.unanswered > 0 {
		deadline = time.Now().Add(c.timeout)
	}

	return c.conn.SetReadDeadline(deadline)
}

// take reports whether the connection can take another query: it is open, and
// either has queries waiting or was idle for no longer than idleTTL. A taken
// connection counts as used now, so the TTL can't run out before the caller
// registers its query.
func (c *muxConn) take(now time.Time, idleTTL time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	waiting := len(c.pending) > c.abandoned

	ok := c.closeErr == nil && (waiting || now.Sub(c.lastUsed) <= idleTTL)
	if ok {
		c.lastUsed = now
	}

	return ok
}

// close tears the connection down once, failing every query still waiting on it.
func (c *muxConn) close(cause error) {
	c.mu.Lock()

	if c.closeErr != nil {
		c.mu.Unlock()

		return
	}

	c.closeErr = fmt.Errorf("%w: %w", errConnClosed, cause)
	close(c.done)

	c.mu.Unlock()

	_ = c.conn.Close()
}

func (c *muxConn) err() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.closeErr
}
