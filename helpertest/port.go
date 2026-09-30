package helpertest

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync"
)

// Test listeners take their ports from NextFreePort rather than from per-file
// constants. Two properties are needed and a constant has neither:
//
//   - The port must be one the kernel will never assign on its own. Everything
//     in the ephemeral range — 32768-60999 on Linux, 49152-65535 on macOS — can
//     be handed to any outbound socket at any moment, so a fixture that names a
//     port in there races every connection the rest of the suite makes. That is
//     what failed CI on a port no fixture mentions (GRA-650).
//   - No two callers may get the same number, including callers in sibling
//     ginkgo processes. Those are separate OS processes, so they cannot share a
//     counter.
//
// The band below sits entirely under the ephemeral range on both platforms,
// which leaves an explicit bind as the only way to occupy it. Inside the band
// the counter never returns a number twice, and each process starts in its own
// slice keyed off its pid. The bind probe covers what is left: a real service on
// the host that happens to sit in the band, or two processes whose pids landed
// in the same slice.
//
// A port is therefore still chosen a moment before its caller binds it, but
// nothing in that window can take it: the kernel does not allocate from this
// band and no other caller will be offered the same number.
const (
	portBandStart = 10000
	portBandEnd   = 32768 // exclusive — the low edge of Linux's ephemeral range
	portSliceSize = 500
	portSlices    = (portBandEnd - portBandStart) / portSliceSize
)

// A package-level cursor is the point: it is what makes "never handed out
// twice in this process" true across every caller.
//
//nolint:gochecknoglobals
var (
	portMu   sync.Mutex
	nextPort = portBandStart + (os.Getpid()%portSlices)*portSliceSize
)

// NextFreePort reserves a port for the caller. The port is bindable at the
// moment it is returned and is never returned again in this process.
func NextFreePort() int {
	portMu.Lock()
	defer portMu.Unlock()

	for range portBandEnd - portBandStart {
		port := nextPort

		nextPort++
		if nextPort >= portBandEnd {
			nextPort = portBandStart
		}

		if portIsFree(port) {
			return port
		}
	}

	// Unreachable short of thousands of live listeners in the band. Panics
	// rather than failing a spec: the helper is called from plain Go tests too.
	panic("helpertest: no bindable port left in the test port band")
}

// NextFreeHostPort is NextFreePort as a "host:port" string.
func NextFreeHostPort(host string) string {
	return HostPort(host, NextFreePort())
}

// HostPort joins a host with a port from NextFreePort.
func HostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// portIsFree reports whether port can be bound for both TCP and UDP. The
// wildcard address is deliberate: a listener on 127.0.0.1 or [::1] conflicts
// with it, so this also rejects a port that is only partly taken.
func portIsFree(port int) bool {
	var (
		ctx     = context.Background()
		lc      = &net.ListenConfig{}
		address = ":" + strconv.Itoa(port)
	)

	ln, err := lc.Listen(ctx, "tcp", address)
	if err != nil {
		return false
	}

	defer ln.Close()

	conn, err := lc.ListenPacket(ctx, "udp", address)
	if err != nil {
		return false
	}

	defer conn.Close()

	return true
}
