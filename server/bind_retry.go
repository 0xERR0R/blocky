package server

import (
	"context"
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
	bindRetryAttempts = 5

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

// retryServe serves via srv.ListenAndServe, retrying while the bind fails: on
// a bind error miekg/dns leaves the server un-started, so calling it again
// simply retries the bind. An error after a successful bind (the listener or
// packet conn is then set) comes from the serving loop and is returned as-is:
// re-calling ListenAndServe would fail with "server already started".
func retryServe(ctx context.Context, srv *dns.Server) error {
	options := append(bindRetryOptions(ctx, srv.Net, srv.Addr),
		retry.RetryIf(func(err error) bool {
			return srv.Listener == nil && srv.PacketConn == nil
		}))

	return retry.Do(func() error { return srv.ListenAndServe() }, options...)
}
