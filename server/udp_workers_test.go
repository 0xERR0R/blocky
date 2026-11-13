package server

import (
	"context"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("UDP workers", func() {
	const (
		queryID = 4711
		probeID = 4712
	)

	// answerQuery replies to a query with one address.
	answerQuery := func(w dns.ResponseWriter, request *dns.Msg) {
		// a handler runs on a goroutine of the server
		defer GinkgoRecover()

		reply := new(dns.Msg).SetReply(request)
		reply.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 1),
		}}

		Expect(w.WriteMsg(reply)).Should(Succeed())
	}

	// serve starts a UDP server on the loopback interface and returns it with its
	// address.
	serve := func(ctx context.Context, handler dns.HandlerFunc, configure func(*dns.Server)) (*dns.Server, string) {
		conn, err := new(net.ListenConfig).ListenPacket(ctx, "udp", "127.0.0.1:0")
		Expect(err).Should(Succeed())

		var (
			started = make(chan struct{})
			served  = make(chan error, 1)
			srv     = &dns.Server{
				PacketConn:        conn,
				Net:               networkUDP,
				Handler:           handler,
				UDPSize:           maxUDPBufferSize,
				NotifyStartedFunc: func() { close(started) },
			}
		)

		if configure != nil {
			configure(srv)
		}

		go func() { served <- srv.ActivateAndServe() }()

		DeferCleanup(func() {
			stopErr := srv.Shutdown()
			if stopErr != nil {
				// the server has not started or has stopped already: Shutdown leaves its socket open
				_ = conn.Close()
			}

			var serveErr error

			Eventually(served).Should(Receive(&serveErr))

			if stopErr == nil {
				Expect(serveErr).Should(Succeed())
			}
		})

		Eventually(started).Should(BeClosed())

		return srv, conn.LocalAddr().String()
	}

	// serveOnWorkers starts a server as serve does and returns its workers too.
	serveOnWorkers := func(ctx context.Context, handler dns.HandlerFunc) (*dns.Server, string, *udpWorkers) {
		var workers *udpWorkers

		srv, address := serve(ctx, handler, func(srv *dns.Server) {
			srv.DecorateReader = func(reader dns.Reader) dns.Reader {
				workers = newUDPWorkers(srv, reader)

				return workers
			}
		})

		return srv, address, workers
	}

	// idleWorkers returns the workers that wait for a query, and how many have started.
	idleWorkers := func(workers *udpWorkers) (idle []chan udpQuery, started int) {
		workers.mu.Lock()
		defer workers.mu.Unlock()

		return slices.Clone(workers.idle), workers.started
	}

	// query returns a packed query, changed by edit before it is packed.
	query := func(id uint16, edit func(*dns.Msg)) []byte {
		msg := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
		msg.Id = id

		if edit != nil {
			edit(msg)
		}

		packed, err := msg.Pack()
		Expect(err).Should(Succeed())

		return packed
	}

	// dial returns the socket of a client of a server.
	dial := func(ctx context.Context, address string) net.Conn {
		conn, err := new(net.Dialer).DialContext(ctx, "udp", address)
		Expect(err).Should(Succeed())
		DeferCleanup(func() { _ = conn.Close() })

		return conn
	}

	// send sends packet from the socket of a client.
	send := func(conn net.Conn, packet []byte) {
		_, err := conn.Write(packet)
		Expect(err).Should(Succeed())
	}

	// receive returns the next packet a server sent to a client.
	receive := func(conn net.Conn) []byte {
		Expect(conn.SetReadDeadline(time.Now().Add(10 * time.Second))).Should(Succeed())

		packet := make([]byte, dns.MaxMsgSize)

		n, err := conn.Read(packet)
		Expect(err).Should(Succeed())

		return packet[:n]
	}

	// replyID returns the ID of a packed message.
	replyID := func(packed []byte) uint16 {
		msg := new(dns.Msg)
		Expect(msg.Unpack(packed)).Should(Succeed())

		return msg.Id
	}

	// exchange sends packet to a server and returns the reply. If the server must not
	// reply, it returns nil once the server has answered a query sent after packet and
	// nothing else has come for a while.
	exchange := func(ctx context.Context, address string, packet []byte, replies bool) []byte {
		conn := dial(ctx, address)

		send(conn, packet)

		if replies {
			return receive(conn)
		}

		send(conn, query(probeID, nil))
		Expect(replyID(receive(conn))).Should(BeEquivalentTo(probeID))

		// a reply to packet may come after the reply to the query
		Expect(conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))).Should(Succeed())

		_, err := conn.Read(make([]byte, dns.MaxMsgSize))
		Expect(err).Should(MatchError(os.ErrDeadlineExceeded))

		return nil
	}

	DescribeTable("answer a packet as dns.Server does",
		func(ctx context.Context, packet func() []byte, replies bool) {
			_, plain := serve(ctx, answerQuery, nil)
			_, onWorkers := serve(ctx, answerQuery, serveUDPOnWorkers)

			expected := exchange(ctx, plain, packet(), replies)

			Expect(exchange(ctx, onWorkers, packet(), replies)).Should(Equal(expected))
		},
		Entry("a query", func() []byte { return query(queryID, nil) }, true),
		Entry("a query with an OPT record", func() []byte {
			return query(queryID, func(msg *dns.Msg) { msg.SetEdns0(dns.DefaultMsgSize, true) })
		}, true),
		Entry("a query with an opcode it does not implement", func() []byte {
			return query(queryID, func(msg *dns.Msg) { msg.Opcode = dns.OpcodeUpdate })
		}, true),
		Entry("a query with two questions and the reserved flag", func() []byte {
			return query(queryID, func(msg *dns.Msg) {
				msg.Zero = true
				msg.Question = append(msg.Question, dns.Question{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
			})
		}, true),
		Entry("a query that ends in its question", func() []byte {
			packed := query(queryID, nil)

			return packed[:len(packed)-3]
		}, true),
		Entry("a query whose header counts three additional records", func() []byte {
			packed := query(queryID, nil)
			packed[11] = 3

			return packed
		}, true),
		Entry("a query whose header counts an additional record it does not have", func() []byte {
			packed := query(queryID, nil)
			packed[11] = 1

			return packed
		}, true),
		Entry("a query with an answer and the start of an additional record", func() []byte {
			packed := query(queryID, func(msg *dns.Msg) {
				msg.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(192, 0, 2, 2),
				}}
			})
			packed[11] = 1

			// the root name and the type OPT, without the rest of the record
			return append(packed, 0, 0, 41)
		}, true),
		Entry("a response", func() []byte {
			return query(queryID, func(msg *dns.Msg) { msg.Response = true })
		}, false),
		Entry("a packet shorter than a header", func() []byte { return []byte{1, 2, 3} }, false),
	)

	It("answer queries that come one after the other on one goroutine", func(ctx context.Context) {
		_, address, workers := serveOnWorkers(ctx, answerQuery)

		for range 20 {
			Expect(exchange(ctx, address, query(queryID, nil), true)).ShouldNot(BeEmpty())

			// the worker has answered before it is idle again
			Eventually(func(g Gomega) {
				idle, started := idleWorkers(workers)

				g.Expect(idle).Should(HaveLen(1))
				g.Expect(started).Should(Equal(1))
			}).Should(Succeed())
		}
	})

	It("send a reply that a handler writes late to the client of its query", func(ctx context.Context) {
		type lateReply struct {
			w       dns.ResponseWriter
			request *dns.Msg
		}

		kept := make(chan lateReply, 1)

		// keeps the first query and answers the others
		_, address, workers := serveOnWorkers(ctx, func(w dns.ResponseWriter, request *dns.Msg) {
			if request.Id == queryID {
				kept <- lateReply{w, request}

				return
			}

			answerQuery(w, request)
		})

		first := dial(ctx, address)
		send(first, query(queryID, nil))

		var late lateReply

		Eventually(kept).Should(Receive(&late))

		// the worker that had the first query answers the one of another client
		Eventually(func() []chan udpQuery {
			idle, _ := idleWorkers(workers)

			return idle
		}).Should(HaveLen(1))
		Expect(replyID(exchange(ctx, address, query(probeID, nil), true))).Should(BeEquivalentTo(probeID))

		_, started := idleWorkers(workers)
		Expect(started).Should(Equal(1))

		answerQuery(late.w, late.request)

		Expect(replyID(receive(first))).Should(BeEquivalentTo(queryID))
	})

	It("tell a handler the address of the server", func(ctx context.Context) {
		local := make(chan net.Addr, 1)

		_, address := serve(ctx, func(w dns.ResponseWriter, request *dns.Msg) {
			local <- w.LocalAddr()

			answerQuery(w, request)
		}, serveUDPOnWorkers)

		Expect(exchange(ctx, address, query(queryID, nil), true)).ShouldNot(BeEmpty())
		Expect((<-local).String()).Should(Equal(address))
	})

	It("tell a handler that its response cannot be packed", func(ctx context.Context) {
		packed := make(chan error, 1)

		_, address := serve(ctx, func(w dns.ResponseWriter, request *dns.Msg) {
			reply := new(dns.Msg).SetReply(request)
			// larger than the 12 bits a response code has with EDNS
			reply.Rcode = 1 << 12

			packed <- w.WriteMsg(reply)

			answerQuery(w, request)
		}, serveUDPOnWorkers)

		Expect(exchange(ctx, address, query(queryID, nil), true)).ShouldNot(BeEmpty())
		Expect(<-packed).Should(MatchError(dns.ErrRcode))
	})

	It("answer more queries at a time than there are workers", func(ctx context.Context) {
		const (
			queries uint16 = udpWorkerCount + 50
			clients        = 8
		)

		var (
			arrived = make(chan struct{}, queries)
			hold    [queries]chan struct{}
			release [queries]func()
			conns   [clients]net.Conn
		)

		for id := range hold {
			hold[id] = make(chan struct{})
			release[id] = sync.OnceFunc(func() { close(hold[id]) })
		}

		// holds each query until it is released
		_, address := serve(ctx, func(w dns.ResponseWriter, request *dns.Msg) {
			arrived <- struct{}{}

			<-hold[request.Id]
			answerQuery(w, request)
		}, serveUDPOnWorkers)

		// before the server stops, which waits for its handlers
		DeferCleanup(func() {
			for _, releaseQuery := range release {
				releaseQuery()
			}
		})

		for client := range conns {
			conns[client] = dial(ctx, address)
		}

		// One query and one reply at a time: a socket may not have room for many.
		for id := range queries {
			send(conns[id%clients], query(id, nil))

			select {
			case <-arrived:
			case <-time.After(10 * time.Second):
				Fail("the server did not start to answer a query while it holds others")
			}
		}

		for id := range queries {
			release[id]()

			Expect(replyID(receive(conns[id%clients]))).Should(Equal(id))
		}
	})

	It("answer the queries in flight before the server stops", func(ctx context.Context) {
		var (
			arrived = make(chan struct{})
			hold    = make(chan struct{})
			release = sync.OnceFunc(func() { close(hold) })
		)

		srv, address := serve(ctx, func(w dns.ResponseWriter, request *dns.Msg) {
			close(arrived)
			<-hold
			answerQuery(w, request)
		}, serveUDPOnWorkers)

		DeferCleanup(release)

		client := dial(ctx, address)
		send(client, query(queryID, nil))

		Eventually(arrived).Should(BeClosed())

		stopped := make(chan error, 1)

		go func() { stopped <- srv.Shutdown() }()

		Consistently(stopped, "200ms").ShouldNot(Receive())

		release()

		Eventually(stopped).Should(Receive(BeNil()))
		Expect(replyID(receive(client))).Should(BeEquivalentTo(queryID))
	})

	It("end when the server stops", func(ctx context.Context) {
		srv, address, workers := serveOnWorkers(ctx, answerQuery)

		Expect(exchange(ctx, address, query(queryID, nil), true)).ShouldNot(BeEmpty())

		var worker chan udpQuery

		Eventually(func(g Gomega) {
			idle, _ := idleWorkers(workers)

			g.Expect(idle).Should(HaveLen(1))

			worker = idle[0]
		}).Should(Succeed())

		Expect(srv.Shutdown()).Should(Succeed())

		// a worker ends when the channel of its queries is closed
		Expect(worker).Should(BeClosed())

		idle, started := idleWorkers(workers)
		Expect(idle).Should(BeEmpty())
		Expect(started).Should(BeZero())
	})
})
