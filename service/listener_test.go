package service

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Service Listener", func() {
	var err error

	Describe("NetListener", func() {
		It("uses the given data", func() {
			var nl net.Listener

			endpoint := Endpoint{"proto", ":1"}

			sut := NewNetListener(endpoint, nl)

			var l Listener = sut
			Expect(l.Exposes()).Should(Equal(endpoint))
			Expect(l.String()).Should(Equal(endpoint.String()))
		})
	})

	type entryFuncs struct {
		Listen func(context.Context, Endpoint) (Listener, error)
		Dial   func(ctx context.Context, addr string) (net.Conn, error)
	}

	DescribeTable("Listener Functions",
		func(ctx context.Context, funcs entryFuncs) {
			By("failing for an invalid endpoint", func() {
				endpoint := Endpoint{"proto", "invalid!"}

				_, err := funcs.Listen(ctx, endpoint)
				Expect(err).ShouldNot(Succeed())
			})

			var l Listener
			By("listening on a valid endpoint", func() {
				endpoint := Endpoint{"proto", ":0"}

				l, err = funcs.Listen(ctx, endpoint)
				Expect(err).Should(Succeed())
				DeferCleanup(l.Close)

				Expect(l.Exposes()).Should(Equal(endpoint))
				Expect(l.String()).Should(Equal(endpoint.String()))
			})

			ch := make(chan struct{})
			data := []byte("test")

			// Server goroutine
			go func() {
				defer GinkgoRecover()

				var (
					conn net.Conn
					err  error // separate var to avoid data-race
				)
				By("accepting client connection", func() {
					conn, err = l.Accept()
					Expect(err).Should(Succeed())
					DeferCleanup(conn.Close)
				})

				By("sending data to the client", func() {
					Expect(conn.Write(data)).Should(Equal(len(data)))
				})

				close(ch)
			}()

			var conn net.Conn
			By("connecting to server", func() {
				conn, err = funcs.Dial(ctx, l.Addr().String())
				Expect(err).Should(Succeed())
				DeferCleanup(conn.Close)
			})

			By("receiving the expected data", func() {
				buff := make([]byte, len(data))
				Expect(conn.Read(buff)).Should(Equal(len(data)))
				Expect(buff).Should(Equal(data))
			})

			// Ensure the server goroutine exit before the test ends
			Eventually(ctx, ch).Should(BeClosed())
		},
		Entry("ListenTCP",
			entryFuncs{
				Listen: func(ctx context.Context, endpoint Endpoint) (Listener, error) {
					return ListenTCP(ctx, endpoint)
				},
				Dial: func(ctx context.Context, addr string) (net.Conn, error) {
					return new(net.Dialer).DialContext(ctx, "tcp", addr)
				},
			},
			SpecTimeout(100*time.Millisecond),
		),
		Entry("ListenTLS",
			entryFuncs{
				Listen: func(ctx context.Context, endpoint Endpoint) (Listener, error) {
					return ListenTLS(ctx, endpoint, helpertest.TLSTestServerConfig())
				},
				Dial: func(ctx context.Context, addr string) (net.Conn, error) {
					d := tls.Dialer{
						Config: helpertest.TLSTestClientConfig(),
					}

					return d.DialContext(ctx, "tcp", addr)
				},
			},
			SpecTimeout(100*time.Millisecond),
		),
	)
})
