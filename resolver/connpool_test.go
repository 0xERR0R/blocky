package resolver

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
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

var _ = Describe("muxConn", Label("connPool"), func() {
	type result struct {
		resp *dns.Msg
		err  error
	}

	var (
		ctx    context.Context
		sut    *muxConn
		client *countingConn
		server *dns.Conn
	)

	BeforeEach(func() {
		var cancel context.CancelFunc

		ctx, cancel = context.WithCancel(context.Background())
		DeferCleanup(cancel)

		near, far := net.Pipe()
		client = &countingConn{Conn: near}
		server = &dns.Conn{Conn: far}
		sut = newMuxConn(&dns.Conn{Conn: client}, 2, time.Second, time.Now)

		DeferCleanup(func() {
			sut.close(net.ErrClosed)
			_ = far.Close()
		})
	})

	// send runs a query in the background and delivers its result on the channel.
	send := func(ctx context.Context, msg *dns.Msg) <-chan result {
		ch := make(chan result, 1)

		go func() {
			defer GinkgoRecover()

			resp, _, err := sut.exchange(ctx, msg, time.Now)
			ch <- result{resp, err}
		}()

		return ch
	}

	read := func() *dns.Msg {
		msg, err := server.ReadMsg()
		Expect(err).Should(Succeed())

		return msg
	}

	answer := func(query *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(query)
		Expect(server.WriteMsg(resp)).Should(Succeed())
	}

	questionOf := func(r result) string {
		Expect(r.err).Should(Succeed())

		return r.resp.Question[0].Name
	}

	// viaPool runs a query in the background through a pool whose only
	// connection is sut.
	viaPool := func(msg *dns.Msg) (*connPool, <-chan error) {
		pool := newConnPool(new(dns.Client), 2, time.Minute, time.Second)
		pool.conns["upstream"] = sut

		errs := make(chan error, 1)

		go func() {
			defer GinkgoRecover()

			_, _, err := pool.exchange(ctx, msg, "upstream")
			errs <- err
		}()

		return pool, errs
	}

	It("matches replies that arrive out of order to their queries", func() {
		a := send(ctx, util.NewMsgWithQuestion("a.example.", A))
		first := read()
		b := send(ctx, util.NewMsgWithQuestion("b.example.", A))
		second := read()

		answer(second)
		answer(first)

		Expect(questionOf(<-a)).Should(Equal("a.example."))
		Expect(questionOf(<-b)).Should(Equal("b.example."))
	})

	It("gives in-flight queries distinct IDs and restores each caller's own", func() {
		msgA := util.NewMsgWithQuestion("a.example.", A)
		msgA.Id = 42
		msgB := util.NewMsgWithQuestion("b.example.", A)
		msgB.Id = 42

		a := send(ctx, msgA)
		first := read()
		b := send(ctx, msgB)
		second := read()

		Expect(first.Id).ShouldNot(Equal(second.Id))

		answer(first)
		answer(second)

		for _, r := range []result{<-a, <-b} {
			Expect(r.err).Should(Succeed())
			Expect(r.resp.Id).Should(Equal(uint16(42)))
		}

		// The callers' messages were copied, not rewritten.
		Expect(msgA.Id).Should(Equal(uint16(42)))
		Expect(msgB.Id).Should(Equal(uint16(42)))
	})

	It("keeps the connection while replies keep arriving, however long a timed-out query goes unanswered", func() {
		sut.timeout = 200 * time.Millisecond

		slowCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		DeferCleanup(cancel)

		slow := send(slowCtx, util.NewMsgWithQuestion("slow.example.", A))
		slowQuery := read()
		Expect((<-slow).err).Should(MatchError(context.DeadlineExceeded))

		// Replies 50 ms apart, for longer than the timeout since the slow query was sent.
		for _, name := range []string{"a.example.", "b.example.", "c.example.", "d.example.", "e.example.", "f.example."} {
			r := send(ctx, util.NewMsgWithQuestion(name, A))
			query := read()
			time.Sleep(50 * time.Millisecond)
			answer(query)
			Expect(questionOf(<-r)).Should(Equal(name))
		}

		// The late reply is dropped, freeing its reserved ID.
		answer(slowQuery)
		Eventually(func() int {
			sut.mu.Lock()
			defer sut.mu.Unlock()

			return len(sut.pending)
		}).Should(BeZero())

		Expect(sut.err()).Should(Succeed())
		Expect(client.closes()).Should(BeZero())

		sut.mu.Lock()
		defer sut.mu.Unlock()
		Expect(sut.abandoned).Should(BeZero())
	})

	It("closes the connection when nothing is read for the timeout while a query is unanswered", func() {
		sut.timeout = 50 * time.Millisecond

		pool, errs := viaPool(util.NewMsgWithQuestion("silent.example.", A))
		read()

		var err error

		Eventually(errs).Should(Receive(&err))
		Expect(err).Should(MatchError(errConnClosed))
		// A timeout, so it is left to the caller's retry instead of redialing here.
		Expect(isTimeout(err)).Should(BeTrue())
		Expect(pool.stats().retried).Should(BeZero())
		Eventually(client.closes).Should(Equal(1))
	})

	It("keeps the connection when a query's deadline passes as it is written", func() {
		// The server never answers; keep the read deadline out of the way.
		sut.timeout = 10 * time.Second

		go func(far *dns.Conn) {
			for {
				if _, err := far.ReadMsg(); err != nil {
					return
				}
			}
		}(server)

		for range 200 {
			shortCtx, cancel := context.WithTimeout(ctx, 20*time.Microsecond)
			_, _, _ = sut.exchange(shortCtx, util.NewMsgWithQuestion("a.example.", A), time.Now)
			cancel()

			Expect(sut.err()).Should(Succeed())
		}
	})

	It("expires an idle connection whose only pending queries were abandoned", func() {
		cancelCtx, cancel := context.WithCancel(ctx)

		cancelled := send(cancelCtx, util.NewMsgWithQuestion("a.example.", A))
		read()
		cancel()
		Expect((<-cancelled).err).Should(MatchError(context.Canceled))

		Expect(sut.take(time.Now().Add(2*time.Minute), time.Minute)).Should(BeFalse())
	})

	It("closes the connection on a frame too short to hold a header", func() {
		_, err := server.Write([]byte{1, 2, 3, 4, 5})
		Expect(err).Should(Succeed())

		Eventually(sut.err).Should(MatchError(errConnClosed))
	})

	It("keeps the connection when a query is cancelled before any reply", func() {
		// parallel_best cancels the race's loser, which says nothing about its connection.
		cancelCtx, cancel := context.WithCancel(ctx)

		cancelled := send(cancelCtx, util.NewMsgWithQuestion("loser.example.", A))
		read()
		cancel()

		Expect((<-cancelled).err).Should(MatchError(context.Canceled))
		Expect(sut.err()).Should(Succeed())
		Expect(client.closes()).Should(BeZero())
	})

	It("doesn't write, or close the connection for, a query whose context ended while it waited to be written", func() {
		// net.Pipe blocks a write until the far end reads, so the first query
		// holds the writer while the second waits for it past its deadline.
		first := send(ctx, util.NewMsgWithQuestion("first.example.", A))
		Eventually(func() bool {
			if sut.writeMu.TryLock() {
				sut.writeMu.Unlock()

				return false
			}

			return true
		}).Should(BeTrue(), "the first query should hold the writer")

		shortCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		DeferCleanup(cancel)

		queued := send(shortCtx, util.NewMsgWithQuestion("queued.example.", A))
		Eventually(shortCtx.Done()).Should(BeClosed())

		// Reading the first query frees the writer; the queued one must give up unwritten.
		firstQuery := read()
		Expect((<-queued).err).Should(MatchError(context.DeadlineExceeded))

		answer(firstQuery)
		Expect(questionOf(<-first)).Should(Equal("first.example."))

		next := send(ctx, util.NewMsgWithQuestion("next.example.", A))
		nextQuery := read()
		Expect(nextQuery.Question[0].Name).Should(Equal("next.example."))
		answer(nextQuery)
		Expect(questionOf(<-next)).Should(Equal("next.example."))
		Expect(client.closes()).Should(BeZero())
	})

	// answerMalformed answers query with its ID, then a header announcing one
	// question whose first label runs past the end: framed correctly, but it
	// doesn't unpack. (miekg treats a frame shorter than a header as a framing
	// error, and a header alone as a valid reply.)
	answerMalformed := func(query *dns.Msg) {
		_, err := server.Write([]byte{byte(query.Id >> 8), byte(query.Id), 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 5, 'a'})
		Expect(err).Should(Succeed())
	}

	It("fails only the query whose reply doesn't unpack, and keeps the connection", func() {
		pending := send(ctx, util.NewMsgWithQuestion("a.example.", A))
		answerMalformed(read())

		var failed result

		Eventually(pending).Should(Receive(&failed))
		Expect(failed.err).Should(MatchError(errUnpackReply))
		Expect(sut.err()).Should(Succeed())

		next := send(ctx, util.NewMsgWithQuestion("next.example.", A))
		answer(read())
		Expect(questionOf(<-next)).Should(Equal("next.example."))
	})

	It("doesn't retry a query whose connection is still open", func() {
		pool, errs := viaPool(util.NewMsgWithQuestion("a.example.", A))
		answerMalformed(read())

		Eventually(errs).Should(Receive(MatchError(errUnpackReply)))
		Expect(pool.stats().retried).Should(BeZero())
	})

	It("replaces the connection once too many abandoned queries go unanswered", func() {
		sut.maxAbandoned = 1

		abandon := func(name string) {
			cancelCtx, cancel := context.WithCancel(ctx)

			cancelled := send(cancelCtx, util.NewMsgWithQuestion(name, A))
			read()
			cancel()

			Expect((<-cancelled).err).Should(MatchError(context.Canceled))
		}

		abandon("a.example.")
		Expect(sut.err()).Should(Succeed())

		abandon("b.example.")
		Expect(sut.err()).Should(MatchError(ContainSubstring("abandoned queries still unanswered")))
	})

	It("fails in-flight queries with a redialable error when the server closes the connection", func() {
		pending := send(ctx, util.NewMsgWithQuestion("a.example.", A))
		read()

		Expect(server.Close()).Should(Succeed())

		r := <-pending
		Expect(r.err).Should(MatchError(errConnClosed))
		Expect(shouldRedial(ctx, r.err)).Should(BeTrue())
	})

	It("drops replies with an unknown ID or a mismatched question", func() {
		queryCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		DeferCleanup(cancel)

		pending := send(queryCtx, util.NewMsgWithQuestion("a.example.", A))
		query := read()

		unknownID := new(dns.Msg)
		unknownID.SetReply(query)
		unknownID.Id = query.Id + 1
		Expect(server.WriteMsg(unknownID)).Should(Succeed())

		wrongQuestion := new(dns.Msg)
		wrongQuestion.SetReply(util.NewMsgWithQuestion("other.example.", A))
		wrongQuestion.Id = query.Id
		Expect(server.WriteMsg(wrongQuestion)).Should(Succeed())

		Expect((<-pending).err).Should(MatchError(context.DeadlineExceeded))
	})

	It("holds queries beyond the in-flight limit until a slot frees", func() {
		first := send(ctx, util.NewMsgWithQuestion("a.example.", A))
		firstQuery := read()
		second := send(ctx, util.NewMsgWithQuestion("b.example.", A))
		secondQuery := read()

		third := send(ctx, util.NewMsgWithQuestion("c.example.", A))

		written := make(chan *dns.Msg, 1)

		go func() {
			defer GinkgoRecover()

			msg, err := server.ReadMsg()
			if err == nil {
				written <- msg
			}
		}()

		// The limit is 2, so the third query must not be written yet.
		Consistently(written, 200*time.Millisecond).ShouldNot(Receive())

		answer(firstQuery)
		Expect(questionOf(<-first)).Should(Equal("a.example."))

		var thirdQuery *dns.Msg

		Eventually(written).Should(Receive(&thirdQuery))
		answer(thirdQuery)
		answer(secondQuery)

		Expect(questionOf(<-second)).Should(Equal("b.example."))
		Expect(questionOf(<-third)).Should(Equal("c.example."))
	})
})

var _ = Describe("shouldRedial", Label("connPool"), func() {
	When("a query fails with a connection-level error", func() {
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
