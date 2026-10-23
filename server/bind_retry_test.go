package server

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("startup bind retry", func() {
	// freeAddressAfter occupies an address and frees it shortly after,
	// simulating a listen address whose interface becomes ready during startup
	freeAddressAfter := func(delay time.Duration) string {
		blocker, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).Should(Succeed())

		go func() {
			time.Sleep(delay)
			_ = blocker.Close()
		}()

		return blocker.Addr().String()
	}

	It("waits for the address to become bindable", func(ctx context.Context) {
		listener, err := listenTCPRetry(ctx, freeAddressAfter(100*time.Millisecond))
		Expect(err).Should(Succeed())
		DeferCleanup(func() { _ = listener.Close() })
	})

	It("serves DNS once the address becomes bindable", func(ctx context.Context) {
		started := make(chan struct{})

		srv := &dns.Server{
			Addr:    freeAddressAfter(100 * time.Millisecond),
			Net:     "tcp",
			Handler: dns.NewServeMux(),
			NotifyStartedFunc: func() {
				close(started)
			},
		}

		served := make(chan error, 1)
		go func() { served <- retryServe(srv) }()

		Eventually(started, "6s", "100ms").Should(BeClosed())
		Expect(srv.ShutdownContext(ctx)).Should(Succeed())
		Expect(<-served).Should(Succeed())
	})
})
