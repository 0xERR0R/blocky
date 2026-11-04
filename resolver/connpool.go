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
	errConnClosed  = errors.New("DoT connection closed")
	errUnpackReply = errors.New("can't unpack reply")
)

// connPoolMaxAbandoned bounds the IDs a connection keeps reserved for queries
// that stopped waiting; past it the connection is replaced.
const connPoolMaxAbandoned = 1024

// connPoolMaxAttempts bounds how often a query is sent when its connection
// closes before the reply (RFC 7766 §6.2.4). A server that closes connections
// after some number of queries can close the retry's too; 3 as dohMaxAttempts.
const connPoolMaxAttempts = 3

// connPool pipelines a single upstream client's DoT queries (RFC 7858 §3.3)
// over persistent connections per address.
//
// Safety properties:
//   - A connection carries up to maxInFlight queries; another to the same
//     address is opened only when all are full, so at ordinary load an address
//     has one connection (RFC 7766 §6.2.2).
//   - An address has at most one dial in progress, shared by the queries
//     waiting on it, so a burst can't become a connection storm.
//   - Queries go to the oldest connection with room, so surplus ones idle out.
//   - exchange resends a query whose connection closed under it, up to
//     connPoolMaxAttempts times.
type connPool struct {
	client      *dns.Client
	maxInFlight int
	idleTTL     time.Duration
	// timeout bounds each dial and decides when a connection stopped responding.
	timeout time.Duration

	// now is overridable in tests; socket deadlines use the real clock.
	now func() time.Time

	mu    sync.Mutex
	conns map[string][]*muxConn
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
	err  error
}

func newConnPool(client *dns.Client, maxInFlight int, idleTTL, timeout time.Duration) *connPool {
	return &connPool{
		client:      client,
		maxInFlight: maxInFlight,
		idleTTL:     idleTTL,
		timeout:     timeout,
		now:         time.Now,
		conns:       make(map[string][]*muxConn),
		dials:       make(map[string]*dialCall),
	}
}

func (p *connPool) stats() connPoolStats {
	return connPoolStats{
		dialed:  p.dialed.Load(),
		retried: p.retried.Load(),
	}
}

// openCount returns the number of connections the pool holds.
func (p *connPool) openCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	n := 0
	for _, conns := range p.conns {
		n += len(conns)
	}

	return n
}

// exchange sends msg over one of addr's connections, and sends it again on
// another when the connection closed before the reply for a reason other than
// a timeout.
func (p *connPool) exchange(
	ctx context.Context, msg *dns.Msg, addr string,
) (*dns.Msg, time.Duration, error) {
	for attempt := 1; ; attempt++ {
		conn, err := p.get(ctx, addr)
		if err != nil {
			return nil, 0, err
		}

		resp, rtt, err := conn.exchange(ctx, msg, p.now)
		if err == nil || attempt == connPoolMaxAttempts || conn.err() == nil || !shouldRedial(ctx, err) {
			return resp, rtt, err
		}

		p.retried.Add(1)
	}
}

// get returns a connection to addr with a slot reserved for one query, waiting
// for the address's dial when none has room.
func (p *connPool) get(ctx context.Context, addr string) (*muxConn, error) {
	for {
		p.mu.Lock()

		conn, stale := p.pick(addr)

		var call *dialCall

		if conn == nil {
			call = p.dials[addr]
			if call == nil {
				call = &dialCall{done: make(chan struct{})}
				p.dials[addr] = call

				// Not the caller's cancellation: other queries wait on this dial too.
				go p.dial(context.WithoutCancel(ctx), addr, call)
			}
		}

		p.mu.Unlock()

		// Close outside the lock: tls.Conn.Close writes close_notify and can block.
		for _, c := range stale {
			c.close(net.ErrClosed)
		}

		if conn != nil {
			return conn, nil
		}

		select {
		case <-call.done:
			if call.err != nil {
				return nil, call.err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// pick reserves a slot on the oldest of addr's connections with one free, and
// drops those that closed or sat idle past idleTTL. The caller holds p.mu.
func (p *connPool) pick(addr string) (conn *muxConn, stale []*muxConn) {
	now := p.now()
	all := p.conns[addr]
	kept := all[:0]

	for _, c := range all {
		if !c.usable(now, p.idleTTL) {
			stale = append(stale, c)

			continue
		}

		kept = append(kept, c)

		if conn == nil && c.reserve(now) {
			conn = c
		}
	}

	clear(all[len(kept):])

	if len(kept) == 0 {
		delete(p.conns, addr)
	} else {
		p.conns[addr] = kept
	}

	return conn, stale
}

func (p *connPool) dial(ctx context.Context, addr string, call *dialCall) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	conn, err := p.client.DialContext(ctx, addr)

	p.mu.Lock()
	delete(p.dials, addr)

	if err == nil {
		p.dialed.Add(1)
		p.conns[addr] = append(p.conns[addr], newMuxConn(conn, p.maxInFlight, p.timeout, p.now))
	}
	p.mu.Unlock()

	call.err = err
	close(call.done)
}

// shouldRedial reports whether a failed exchange on a pooled connection should
// be retried transparently on a fresh dial. Only connection-level failures (a
// stale pooled connection) qualify; a cancelled/expired context or a timeout is
// surfaced to the caller so its retry and IP-rotation logic can handle it.
func shouldRedial(ctx context.Context, err error) bool {
	return ctx.Err() == nil && !isTimeout(err)
}

// Close closes every connection; the queries on them are resent, and the pool
// stays usable.
func (p *connPool) Close() error {
	p.mu.Lock()
	conns := p.conns
	p.conns = make(map[string][]*muxConn)
	p.mu.Unlock()

	for _, addrConns := range conns {
		for _, conn := range addrConns {
			conn.close(net.ErrClosed)
		}
	}

	return nil
}

// muxConn is one DoT connection carrying many queries at once. Each query takes
// a slot and is written under an ID unique among the connection's in-flight
// queries (RFC 7766 §6.2.1); one reader goroutine hands each reply to the query
// with its ID and question (RFC 7766 §7).
//
// It closes, failing its queries with the timeout, when a write doesn't finish
// within timeout or nothing is read for timeout while a written query is
// unanswered: a blackholed path accepts writes and never answers.
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

// pendingQuery is a query not yet answered. Its reply channel is nil once the
// caller stopped waiting; the ID stays reserved so the late reply can't answer
// a newer query.
type pendingQuery struct {
	query   *dns.Msg
	written bool
	reply   chan reply
}

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

// reserve takes a free slot, if any, and marks the connection used, so the idle
// TTL can't run out before the query registers.
func (c *muxConn) reserve(now time.Time) bool {
	select {
	case c.slots <- struct{}{}:
	default:
		return false
	}

	c.mu.Lock()
	c.lastUsed = now
	c.mu.Unlock()

	return true
}

// exchange writes a copy of msg under a connection-unique ID, waits for the
// reply with msg's ID restored, and releases the caller's slot.
func (c *muxConn) exchange(
	ctx context.Context, msg *dns.Msg, now func() time.Time,
) (*dns.Msg, time.Duration, error) {
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

// register records the query under an ID no in-flight query uses.
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

	// The context may have ended while the query waited for the writer.
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

// expectReply marks the query written, before its reply can arrive, and arms
// the read deadline if no other query is unanswered.
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
		c.close(fmt.Errorf("more than %d abandoned queries still unanswered", c.maxAbandoned))
	}
}

func (c *muxConn) readLoop(now func() time.Time) {
	for {
		resp, err := c.conn.ReadMsg()
		if resp == nil {
			// An I/O error, a short frame or the read deadline: the stream is lost.
			c.close(err)

			return
		}

		r := reply{msg: resp}
		if err != nil {
			// Only the body failed to unpack; the stream is in sync.
			r = reply{err: fmt.Errorf("%w: %w", errUnpackReply, err)}
		}

		if err := c.deliver(resp, r, now()); err != nil {
			c.close(err)

			return
		}
	}
}

// deliver hands r to the written query with resp's ID and question, dropping it
// otherwise. Any frame shows the path is alive, so the read deadline restarts
// while queries are unanswered.
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

// usable reports whether the connection is open and either busy or idle for no
// longer than idleTTL.
func (c *muxConn) usable(now time.Time, idleTTL time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	waiting := len(c.pending) > c.abandoned

	return c.closeErr == nil && (waiting || now.Sub(c.lastUsed) <= idleTTL)
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
