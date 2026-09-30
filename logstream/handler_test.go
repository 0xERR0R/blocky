// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package logstream_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"time"

	"github.com/0xERR0R/blocky/logstream"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"nhooyr.io/websocket"
)

var _ = Describe("WebSocket Handler", func() {
	var (
		b      *logstream.Broadcaster
		srv    *httptest.Server
		ctx    context.Context
		cancel context.CancelFunc
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())
		DeferCleanup(cancel)

		b = logstream.NewBroadcaster(ctx, 100)
		srv = httptest.NewServer(logstream.Handler(b))
		DeferCleanup(srv.Close)
	})

	It("streams log entries over WebSocket", func() {
		conn := dialAndSubscribe(ctx, b, wsURL(srv))

		b.Publish(entry("ws-test"))

		Expect(readEntry(ctx, conn).Message).Should(Equal("ws-test"))
	})

	It("backfills existing entries on connect", func() {
		b.Publish(entry("before-connect"))

		conn := dial(ctx, wsURL(srv))

		Expect(readEntry(ctx, conn).Message).Should(Equal("before-connect"))
	})

	It("sends close frame on shutdown", func() {
		conn := dialAndSubscribe(ctx, b, wsURL(srv))

		b.Shutdown()

		readCtx, cancelRead := context.WithTimeout(ctx, readTimeout)
		defer cancelRead()

		_, _, err := conn.Read(readCtx)
		Expect(err).Should(HaveOccurred())
		Expect(readCtx.Err()).Should(Succeed(), "no close frame arrived before the deadline")

		// Not just "some error": a reset or an EOF would satisfy that, and the
		// point of the spec is the frame the handler sends on a closed channel.
		Expect(websocket.CloseStatus(err)).Should(Equal(websocket.StatusGoingAway))
	})

	It("closes a connection that upgrades after shutdown", func() {
		// The other half of Broadcaster.Shutdown: a handler that reaches
		// Subscribe after the shutdown gets an already-closed channel, so it
		// still sends the close frame rather than blocking on a channel nobody
		// will close again.
		b.Shutdown()

		conn := dial(ctx, wsURL(srv))

		readCtx, cancelRead := context.WithTimeout(ctx, readTimeout)
		defer cancelRead()

		_, _, err := conn.Read(readCtx)
		Expect(readCtx.Err()).Should(Succeed(), "no close frame arrived before the deadline")
		Expect(websocket.CloseStatus(err)).Should(Equal(websocket.StatusGoingAway))
	})
})

// Every read in this file used to run on the spec context, which is cancelled
// only in cleanup. A handler that never wrote therefore blocked the suite
// instead of failing it — one spec here held a CI runner for 20 minutes until
// it was cancelled by hand. See GRA-650.
const readTimeout = 5 * time.Second

func wsURL(srv *httptest.Server) string {
	return "ws" + srv.URL[4:]
}

// readEntry reads one entry, with a deadline.
func readEntry(ctx context.Context, conn *websocket.Conn) logstream.LogEntry {
	GinkgoHelper()

	readCtx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	_, data, err := conn.Read(readCtx)
	Expect(err).Should(Succeed())

	var received logstream.LogEntry
	Expect(json.Unmarshal(data, &received)).Should(Succeed())

	return received
}

func dial(ctx context.Context, url string) *websocket.Conn {
	GinkgoHelper()

	dialCtx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	conn, _, err := websocket.Dial(dialCtx, url, nil)
	Expect(err).Should(Succeed())
	DeferCleanup(func() { _ = conn.CloseNow() })

	return conn
}

// dialAndSubscribe connects and returns only once the handler has reached
// Broadcaster.Subscribe.
//
// websocket.Dial returns on the 101 response, which is several statements
// before the handler subscribes, and a Publish in that window reaches nobody —
// Publish gives up on a contended lock, and the contending holder is that very
// Subscribe call. A spec that needs the entry it publishes to be delivered has
// to wait for the subscription first.
//
// An entry published before the dial is already in the ring buffer, and
// Subscribe reads the backfill under the lock, so it cannot be missed. Reading
// that entry back is therefore proof that the subscription exists.
//
// The same window used to hang the shutdown spec, and that half was a real
// defect rather than a test artifact: Shutdown closed no subscribers, the
// handler then blocked forever on a channel nobody would close, and the close
// frame never came. Broadcaster.Subscribe now returns a closed channel after
// Shutdown, so specs no longer need this helper to test that path.
func dialAndSubscribe(ctx context.Context, b *logstream.Broadcaster, url string) *websocket.Conn {
	GinkgoHelper()

	b.Publish(entry("subscribe-handshake"))

	conn := dial(ctx, url)

	Expect(readEntry(ctx, conn).Message).Should(Equal("subscribe-handshake"))

	return conn
}
