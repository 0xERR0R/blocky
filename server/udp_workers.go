package server

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

const (
	// queryStackSize is the call frame a goroutine makes room for before it answers UDP
	// queries, see util.GrowStack. A goroutine starts with a small stack, typically
	// 2 KiB, which the runtime doubles until the frame fits. That typically gives it
	// 16 KiB, and most queries are answered without growing the stack again.
	queryStackSize = 8 << 10

	// udpWorkerCount is how many goroutines a UDP server keeps to answer queries. A
	// query that arrives while all of them are busy gets a goroutine of its own.
	udpWorkerCount = 256

	dnsHeaderSize = 12
)

// udpWorkers answers the queries of a UDP server on goroutines it keeps.
//
// dns.Server starts a goroutine for each UDP query and sets a read deadline before it
// reads each packet. A new goroutine has a small stack, which the runtime grows by
// copying it. A worker keeps the stack it has grown from one query to the next, though
// the garbage collector may shrink the stack of a worker that waits. The socket needs
// no read deadline: the server sets one that has passed when it stops.
//
// udpWorkers is the dns.Reader of the server. ReadUDP hands each packet it reads to a
// worker and reads the next one. It returns to the server only with the error that ends
// reading, so the server starts no goroutines of its own.
//
// Of what a dns.Server can be set up to do with a UDP query, the workers leave out TSIG,
// DecorateWriter and MsgInvalidFunc.
type udpWorkers struct {
	dns.Reader // reads TCP, which a UDP server never does

	accept  dns.MsgAcceptFunc
	handler dns.Handler
	packets sync.Pool // *[]byte, each as large as the largest UDP packet

	mu sync.Mutex
	// idle has the workers that wait for a query. The one that has waited the shortest
	// gets the next query: its stack is the most likely to be in the CPU's cache.
	idle    []chan udpQuery
	started int

	// inFlight counts the queries that are read and not answered yet
	inFlight sync.WaitGroup
}

// udpQuery is a packet the server has read, with the socket and the client it came from.
type udpQuery struct {
	conn    *net.UDPConn
	session *dns.SessionUDP
	packet  *[]byte
	size    int
}

// serveUDPOnWorkers makes srv, which must not have started, answer its queries on
// goroutines it keeps.
func serveUDPOnWorkers(srv *dns.Server) {
	srv.DecorateReader = func(reader dns.Reader) dns.Reader {
		return newUDPWorkers(srv, reader)
	}
}

// newUDPWorkers returns the workers of srv. The server calls it when it starts to serve,
// with the reader it has for TCP.
func newUDPWorkers(srv *dns.Server, reader dns.Reader) *udpWorkers {
	return &udpWorkers{
		Reader:  reader,
		accept:  srv.MsgAcceptFunc,
		handler: srv.Handler,
		packets: sync.Pool{New: func() any {
			packet := make([]byte, srv.UDPSize)

			return &packet
		}},
	}
}

// ReadUDP implements `dns.Reader`.
func (p *udpWorkers) ReadUDP(conn *net.UDPConn, _ time.Duration) ([]byte, *dns.SessionUDP, error) {
	for {
		packet, _ := p.packets.Get().(*[]byte)

		size, session, err := dns.ReadFromSessionUDP(conn, *packet)
		if err != nil {
			p.packets.Put(packet)
			// The workers answer their queries before any read error goes to the
			// server, which stops or cannot read its socket anymore. The server would
			// read again after a temporary error. None is expected: nothing but a server
			// that stops sets a read deadline on the socket.
			p.stop()

			return nil, nil, err
		}

		if size < dnsHeaderSize {
			p.packets.Put(packet)

			continue
		}

		p.dispatch(udpQuery{conn: conn, session: session, packet: packet, size: size})
	}
}

// dispatch hands query to a worker, or to a new goroutine if all workers are busy.
func (p *udpWorkers) dispatch(query udpQuery) {
	p.inFlight.Add(1)

	var worker chan udpQuery

	p.mu.Lock()

	if last := len(p.idle) - 1; last >= 0 {
		worker, p.idle = p.idle[last], p.idle[:last]
	} else if p.started < udpWorkerCount {
		p.started++
		// holds one query: a worker is in idle before it waits for its next query
		worker = make(chan udpQuery, 1)

		go p.work(worker)
	}

	p.mu.Unlock()

	if worker == nil {
		go func() {
			p.answer(query, true)
			p.inFlight.Done()
		}()

		return
	}

	worker <- query
}

// work answers the queries of one worker until stop closes their channel.
func (p *udpWorkers) work(queries chan udpQuery) {
	util.GrowStack[[queryStackSize]byte]()

	for query := range queries {
		p.answer(query, false)

		p.mu.Lock()
		p.idle = append(p.idle, queries)
		p.mu.Unlock()

		// only now: stop ends the workers it finds in idle once no query is in flight
		p.inFlight.Done()
	}
}

// stop ends the workers once the queries in flight are answered, as dns.Server does
// with its own goroutines before it closes the socket. Reading may start again.
func (p *udpWorkers) stop() {
	p.inFlight.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, worker := range p.idle {
		close(worker)
	}

	p.idle, p.started = nil, 0
}

// answer does with a packet what dns.Server does with it: it ignores a response,
// rejects a query it does not accept or cannot unpack, and calls the handler with the
// others. newGoroutine tells that the stack of the goroutine has not grown yet.
func (p *udpWorkers) answer(query udpQuery, newGoroutine bool) {
	packet := (*query.packet)[:query.size]

	action := p.accept(dns.Header{
		Id:      binary.BigEndian.Uint16(packet),
		Bits:    binary.BigEndian.Uint16(packet[2:]),
		Qdcount: binary.BigEndian.Uint16(packet[4:]),
		Ancount: binary.BigEndian.Uint16(packet[6:]),
		Nscount: binary.BigEndian.Uint16(packet[8:]),
		Arcount: binary.BigEndian.Uint16(packet[10:]),
	})

	// the goroutine of a packet the server ignores or rejects keeps its small stack
	if action == dns.MsgAccept && newGoroutine {
		util.GrowStack[[queryStackSize]byte]()
	}

	var (
		request = new(dns.Msg)
		err     error
	)

	switch action {
	case dns.MsgAccept:
		err = request.Unpack(packet)
	case dns.MsgReject, dns.MsgRejectNotImplemented:
		// only the header: the reply to a rejected query has no sections
		err = request.Unpack(packet[:dnsHeaderSize])
	case dns.MsgIgnore:
	}

	p.packets.Put(query.packet)

	if action == dns.MsgIgnore {
		return
	}

	// one per query: a handler may keep its writer
	w := &udpResponseWriter{conn: query.conn, session: query.session}

	if action == dns.MsgAccept && err == nil {
		p.handler.ServeDNS(w, request)

		return
	}

	opcode := request.Opcode

	request.SetRcodeFormatError(request)
	request.Zero = false

	if action == dns.MsgRejectNotImplemented {
		request.Opcode = opcode
		request.Rcode = dns.RcodeNotImplemented
	}

	request.Ns, request.Answer, request.Extra = nil, nil, nil

	_ = w.WriteMsg(request)
}

// udpResponseWriter sends the response to a UDP query from the address the query came
// to.
type udpResponseWriter struct {
	conn    *net.UDPConn
	session *dns.SessionUDP
}

// LocalAddr implements `dns.ResponseWriter`.
func (w *udpResponseWriter) LocalAddr() net.Addr { return w.conn.LocalAddr() }

// RemoteAddr implements `dns.ResponseWriter`.
func (w *udpResponseWriter) RemoteAddr() net.Addr { return w.session.RemoteAddr() }

// WriteMsg implements `dns.ResponseWriter`.
func (w *udpResponseWriter) WriteMsg(m *dns.Msg) error {
	packed, err := m.Pack()
	if err != nil {
		return err
	}

	_, err = w.Write(packed)

	return err
}

// Write implements `dns.ResponseWriter`.
func (w *udpResponseWriter) Write(packed []byte) (int, error) {
	return dns.WriteToSessionUDP(w.conn, packed, w.session)
}

// Close implements `dns.ResponseWriter`. The socket is the server's.
func (w *udpResponseWriter) Close() error { return nil }

// TsigStatus implements `dns.ResponseWriter`. The server has no TSIG keys.
func (w *udpResponseWriter) TsigStatus() error { return nil }

// TsigTimersOnly implements `dns.ResponseWriter`.
func (w *udpResponseWriter) TsigTimersOnly(bool) {}

// Hijack implements `dns.ResponseWriter`.
func (w *udpResponseWriter) Hijack() {}
