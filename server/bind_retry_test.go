package server

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("startup bind retry", func() {
	// occupyTCP reserves a TCP address and releases it after delay, simulating
	// a listen address whose interface becomes ready during startup.
	occupyTCP := func(delay time.Duration) string {
		blocker, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).Should(Succeed())

		go func() {
			time.Sleep(delay)
			_ = blocker.Close()
		}()

		return blocker.Addr().String()
	}

	// occupyUDP reserves a UDP address and releases it after delay.
	occupyUDP := func(delay time.Duration) string {
		blocker, err := net.ListenPacket("udp", "127.0.0.1:0")
		Expect(err).Should(Succeed())

		go func() {
			time.Sleep(delay)
			_ = blocker.Close()
		}()

		return blocker.LocalAddr().String()
	}

	Describe("listenTCPRetry", func() {
		It("binds once the address becomes available", func(ctx context.Context) {
			listener, err := listenTCPRetry(ctx, occupyTCP(100*time.Millisecond))
			Expect(err).Should(Succeed())
			DeferCleanup(func() { _ = listener.Close() })
		})

		It("returns the context error when cancelled while retrying", func(ctx context.Context) {
			blocker, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).Should(Succeed())
			DeferCleanup(func() { _ = blocker.Close() })

			retryCtx, cancel := context.WithCancel(ctx)
			go func() {
				time.Sleep(50 * time.Millisecond)
				cancel()
			}()

			_, err = listenTCPRetry(retryCtx, blocker.Addr().String())
			Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		})
	})

	Describe("listenPacketRetry", func() {
		It("binds once the address becomes available", func(ctx context.Context) {
			pc, err := listenPacketRetry(ctx, occupyUDP(100*time.Millisecond))
			Expect(err).Should(Succeed())
			DeferCleanup(func() { _ = pc.Close() })
		})

		It("returns the context error when cancelled while retrying", func(ctx context.Context) {
			blocker, err := net.ListenPacket("udp", "127.0.0.1:0")
			Expect(err).Should(Succeed())
			DeferCleanup(func() { _ = blocker.Close() })

			retryCtx, cancel := context.WithCancel(ctx)
			go func() {
				time.Sleep(50 * time.Millisecond)
				cancel()
			}()

			_, err = listenPacketRetry(retryCtx, blocker.LocalAddr().String())
			Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		})
	})

	Describe("retryServe", func() {
		It("serves DNS once the address becomes available", func(ctx context.Context) {
			started := make(chan struct{})

			srv := &dns.Server{
				Addr:    occupyTCP(100 * time.Millisecond),
				Net:     "tcp",
				Handler: dns.NewServeMux(),
				NotifyStartedFunc: func() {
					close(started)
				},
			}

			served := make(chan error, 1)
			go func() { served <- retryServe(ctx, srv) }()

			Eventually(started, "6s", "100ms").Should(BeClosed())
			Expect(srv.ShutdownContext(ctx)).Should(Succeed())
			Expect(<-served).Should(Succeed())
		})

		It("returns the context error when cancelled while retrying", func(ctx context.Context) {
			blocker, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).Should(Succeed())
			DeferCleanup(func() { _ = blocker.Close() })

			srv := &dns.Server{
				Addr:    blocker.Addr().String(),
				Net:     "tcp",
				Handler: dns.NewServeMux(),
			}

			retryCtx, cancel := context.WithCancel(ctx)
			go func() {
				time.Sleep(50 * time.Millisecond)
				cancel()
			}()

			Expect(errors.Is(retryServe(retryCtx, srv), context.Canceled)).To(BeTrue())
		})
	})
})
