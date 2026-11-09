package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/miekg/dns"
)

// At system boot, the network interface that owns a configured listen address
// (e.g. ports.dns: "192.168.1.2:53") may not exist yet or may not have its
// address assigned, so the socket bind fails ("cannot assign requested
// address"). Instead of exiting on the first error, blocky retries each bind
// for a short grace period and only hard fails if the interface never comes up.
const (
	// bindRetryAttempts is the total number of bind attempts (the initial
	// attempt plus bindRetryAttempts-1 retries) before giving up.
	bindRetryAttempts = 10

	// bindRetryDelay is the wait between two bind attempts.
	bindRetryDelay = 500 * time.Millisecond
)

// bindRetryOptions returns the retry options shared by all startup binds: a
// fixed delay, a bounded number of attempts, and a warning log on each retry.
// The context makes the retry loop abort promptly when startup is cancelled.
func bindRetryOptions(ctx context.Context, network, address string) []retry.Option {
	return []retry.Option{
		retry.Context(ctx),
		retry.Attempts(bindRetryAttempts),
		retry.DelayType(retry.FixedDelay),
		retry.Delay(bindRetryDelay),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(n uint, err error) {
			logger().Warnf("could not bind %s listener on %s (attempt %d/%d), "+
				"the interface may not be up yet, retrying in %v: %v",
				network, address, n+1, bindRetryAttempts, bindRetryDelay, err)
		}),
	}
}

// listenTCPRetry binds a TCP listener, retrying while the interface owning the
// address comes up. Retrying is safe: a failed bind leaves no state behind.
func listenTCPRetry(ctx context.Context, address string) (net.Listener, error) {
	lc := &net.ListenConfig{}

	var listener net.Listener

	err := retry.Do(
		func() error {
			var err error
			listener, err = lc.Listen(ctx, networkTCP, address)

			return err
		},
		bindRetryOptions(ctx, networkTCP, address)...,
	)

	return listener, err
}

// listenPacketRetry binds a UDP packet connection, retrying while the interface
// owning the address comes up.
func listenPacketRetry(ctx context.Context, address string) (net.PacketConn, error) {
	lc := &net.ListenConfig{}

	var pc net.PacketConn

	err := retry.Do(
		func() error {
			var err error
			pc, err = lc.ListenPacket(ctx, networkUDP, address)

			return err
		},
		bindRetryOptions(ctx, networkUDP, address)...,
	)

	return pc, err
}

// bindDNSServer binds the server's socket, retrying while the interface owning
// the address comes up. On success it sets srv.Listener or srv.PacketConn so
// the server can subsequently be started with ActivateAndServe.
func bindDNSServer(ctx context.Context, srv *dns.Server) error {
	switch srv.Net {
	case networkUDP:
		pc, err := listenPacketRetry(ctx, srv.Addr)
		if err != nil {
			return err
		}

		srv.PacketConn = pc
	case networkTCP:
		l, err := listenTCPRetry(ctx, srv.Addr)
		if err != nil {
			return err
		}

		srv.Listener = l
	case networkTCPTLS:
		l, err := listenTCPRetry(ctx, srv.Addr)
		if err != nil {
			return err
		}

		srv.Listener = tls.NewListener(l, srv.TLSConfig)
	default:
		return fmt.Errorf("unsupported DNS listener network %q", srv.Net)
	}

	return nil
}

// retryServe binds the server's socket (retrying while the interface owning the
// address comes up) and then serves it. Binding and serving are split so that a
// cancelled context aborts the in-progress bind (net.Listen respects the
// context) and stops the serve loop, rather than leaving a half-started server.
func retryServe(ctx context.Context, srv *dns.Server) error {
	if srv.Listener == nil && srv.PacketConn == nil {
		if err := bindDNSServer(ctx, srv); err != nil {
			return err
		}
	}

	return serveDNSServer(ctx, srv)
}

// serveDNSServer serves an already-bound server and stops it when ctx is
// cancelled. A goroutine watches the context: if the server is already serving,
// it shuts it down gracefully; if it has not reached a serving state yet (the
// bind completed but ActivateAndServe below has not set the server's started
// flag), the socket is closed directly so that the pending ActivateAndServe
// fails instead of serving forever.
func serveDNSServer(ctx context.Context, srv *dns.Server) error {
	stop := make(chan struct{})
	defer close(stop)

	go func() {
		select {
		case <-ctx.Done():
		case <-stop:
			return
		}

		if err := srv.Shutdown(); err != nil {
			closeServerSocket(srv)
		}
	}()

	err := srv.ActivateAndServe()
	if ctx.Err() != nil {
		// The server was stopped as part of a shutdown; an error from
		// ActivateAndServe (e.g. a closed socket) is expected and not a
		// startup failure.
		return nil
	}

	return err
}

// closeServerSocket closes a bound server socket directly. It is only used as a
// fallback when the server is cancelled before it reaches a serving state, so
// there are no in-flight connections to drain.
func closeServerSocket(srv *dns.Server) {
	if srv.Listener != nil {
		_ = srv.Listener.Close()
	}

	if srv.PacketConn != nil {
		_ = srv.PacketConn.Close()
	}
}
