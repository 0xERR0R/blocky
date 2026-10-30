package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// At system boot, the network interface that owns a configured listen address
// (e.g. ports.dns: "192.168.1.2:53") may not exist yet or may not have its
// address assigned, so the socket bind fails ("cannot assign requested
// address"). Instead of exiting on the first error, blocky retries each bind
// for a short grace period and only hard fails if the interface never comes up.
const (
	// bindRetryAttempts is the total number of bind attempts before giving up.
	bindRetryAttempts = 12
	// bindRetryDelay is the wait between two bind attempts.
	bindRetryDelay = 500 * time.Millisecond
)

// listenTCPRetry binds a TCP listener like net.ListenConfig.Listen, retrying
// failed binds (see above). Retrying is safe: a failed bind leaves no state.
func listenTCPRetry(ctx context.Context, address string) (net.Listener, error) {
	var lc net.ListenConfig

	for attempt := 1; ; attempt++ {
		listener, err := lc.Listen(ctx, networkTCP, address)
		if err == nil {
			return listener, nil
		}

		if attempt == bindRetryAttempts {
			return nil, fmt.Errorf("bind failed after %d attempts: %w", bindRetryAttempts, err)
		}

		logger().Warnf("could not bind %s (attempt %d/%d), the interface may not be up yet, "+
			"retrying in %v: %v", address, attempt, bindRetryAttempts, bindRetryDelay, err)

		time.Sleep(bindRetryDelay)
	}
}

// retryServe serves via srv.ListenAndServe, retrying while the bind fails: on
// a bind error miekg/dns leaves the server un-started, so calling it again
// simply retries the bind. An error after a successful bind (the listener or
// packet conn is then set) comes from the serving loop and is returned as-is:
// re-calling ListenAndServe would fail with "server already started".
func retryServe(srv *dns.Server) error {
	for attempt := 1; ; attempt++ {
		err := srv.ListenAndServe()
		if err == nil {
			return nil
		}

		// serve errors only occur after a successful bind, do not retry those
		if srv.Listener != nil || srv.PacketConn != nil || attempt == bindRetryAttempts {
			return err
		}

		logger().Warnf("could not bind %s server on %s (attempt %d/%d), the interface may not be up yet, "+
			"retrying in %v: %v", srv.Net, srv.Addr, attempt, bindRetryAttempts, bindRetryDelay, err)

		time.Sleep(bindRetryDelay)
	}
}
