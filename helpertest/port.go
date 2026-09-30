package helpertest

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/onsi/ginkgo/v2"
)

// Test listeners take their ports from NextFreePort rather than from per-file
// constants. Two properties are needed and a constant has neither:
//
//   - The port must be one the kernel will never assign on its own. Everything
//     in the ephemeral range — 32768-60999 by default on Linux, 49152-65535 on
//     macOS — can be handed to any outbound socket at any moment, so a fixture
//     that names a port in there races every connection the rest of the suite
//     makes. That is what failed CI on a port no fixture mentions (GRA-650).
//   - No two callers may get the same number, including callers in sibling
//     ginkgo processes. Those are separate OS processes, so they cannot share a
//     counter.
//
// The band below sits under the default ephemeral range, which leaves an
// explicit bind as the only way to occupy it — and checkPortBand verifies that
// on Linux rather than assuming it, because ip_local_port_range is
// configurable. Inside the band, each process takes its own slice and the
// cursor does not repeat until the whole band is exhausted, which no suite here
// comes close to. The bind probe then covers what is left: a real service on the
// host sitting in the band, or a process with no ginkgo index to key off.
//
// A port is therefore still chosen a moment before its caller binds it, but
// nothing in that window can take it: the kernel does not allocate from this
// band, and no other caller will be offered the same number.
const (
	portBandStart = 10000
	portBandLimit = 32768 // the low edge of Linux's default ephemeral range
	portSliceSize = 250
	portSlices    = (portBandLimit - portBandStart) / portSliceSize
	// Exclusive, and aligned to portSliceSize so that every slice is full.
	portBandEnd = portBandStart + portSlices*portSliceSize
)

// The cursor is package-level on purpose: it is what makes "no caller is offered
// a number another caller already has" true. Zero means "not seeded yet".
// Seeding is deferred to the first call rather than done in the initializer
// below, because Go parses the test binary's flags after package-level
// initializers run — an initializer would read ginkgo's defaults and put every
// sibling process in slice 0.
//
//nolint:gochecknoglobals
var (
	portMu     sync.Mutex
	portCursor int
)

// NextFreePort reserves a port for the caller. The port is bindable at the
// moment it is returned and is not offered to any other caller.
func NextFreePort() int {
	portMu.Lock()
	defer portMu.Unlock()

	if portCursor == 0 {
		checkPortBand()

		portCursor = portBandStart + portSeedSlice()*portSliceSize
	}

	for range portBandEnd - portBandStart {
		port := portCursor

		portCursor++
		if portCursor >= portBandEnd {
			portCursor = portBandStart
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

// portSeedSlice picks this process's slice of the band.
//
// ginkgo's process index is 1-based and collision-free by construction, which
// is exactly the property wanted. It comes from a flag, so by the time any test
// runs it is correct — including a plain Go test in the same binary, which runs
// before RunSpecs. Verified: under `ginkgo -p -procs=4`, the four processes seed
// slices 0-3 from both a plain Test function and a spec.
//
// The pid covers a run with no ginkgo process index at all (plain `go test`, one
// process per package): not collision-free, but distinct per process, and the
// bind probe catches any overlap that survives.
func portSeedSlice() int {
	if cfg, _ := ginkgo.GinkgoConfiguration(); cfg.ParallelTotal > 1 {
		return (cfg.ParallelProcess - 1) % portSlices
	}

	return os.Getpid() % portSlices
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

// checkPortBand fails loudly if the kernel allocates ephemeral ports from the
// band this file hands out.
//
// The whole scheme rests on the band being reserved for explicit binds, and
// ip_local_port_range is a sysctl: hosts do ship with `1024 65535`, and
// FreeBSD's default low edge is 10000. Where that is true the original
// flakiness comes back with no diagnostic at all, which is the one outcome
// worse than the bug. Saying so on the first port request is the point.
//
// Reads the Linux sysctl only; elsewhere there is nothing portable to read and
// the documented defaults leave the band clear.
func checkPortBand() {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return
	}

	fields := strings.Fields(string(raw))
	if len(fields) != 2 {
		return
	}

	low, lowErr := strconv.Atoi(fields[0])
	high, highErr := strconv.Atoi(fields[1])

	if lowErr != nil || highErr != nil {
		return
	}

	if low < portBandEnd && high >= portBandStart {
		panic(fmt.Sprintf(
			"helpertest: net.ipv4.ip_local_port_range is %d-%d, which overlaps the "+
				"test port band %d-%d. The kernel would assign ports this suite binds "+
				"explicitly, which produces random \"bind: address already in use\" "+
				"failures. Raise the range above %d, or move the band in helpertest/port.go.",
			low, high, portBandStart, portBandEnd-1, portBandEnd))
	}
}
