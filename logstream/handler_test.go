package logstream_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"

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
		conn, _, err := websocket.Dial(ctx, "ws"+srv.URL[4:], nil)
		Expect(err).Should(Succeed())
		defer conn.CloseNow() //nolint:errcheck

		b.Publish(entry("ws-test"))

		_, data, err := conn.Read(ctx)
		Expect(err).Should(Succeed())

		var received logstream.LogEntry
		Expect(json.Unmarshal(data, &received)).Should(Succeed())
		Expect(received.Message).Should(Equal("ws-test"))
	})

	It("backfills existing entries on connect", func() {
		b.Publish(entry("before-connect"))

		conn, _, err := websocket.Dial(ctx, "ws"+srv.URL[4:], nil)
		Expect(err).Should(Succeed())
		defer conn.CloseNow() //nolint:errcheck

		_, data, err := conn.Read(ctx)
		Expect(err).Should(Succeed())

		var received logstream.LogEntry
		Expect(json.Unmarshal(data, &received)).Should(Succeed())
		Expect(received.Message).Should(Equal("before-connect"))
	})

	It("sends close frame on shutdown", func() {
		conn, _, err := websocket.Dial(ctx, "ws"+srv.URL[4:], nil)
		Expect(err).Should(Succeed())
		defer conn.CloseNow() //nolint:errcheck

		b.Shutdown()

		_, _, err = conn.Read(ctx)
		Expect(err).Should(HaveOccurred())
	})
})
