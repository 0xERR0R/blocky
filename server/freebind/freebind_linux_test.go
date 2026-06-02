//go:build linux

package freebind_test

import (
	"context"
	"net"

	"github.com/0xERR0R/blocky/server/freebind"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// 192.0.2.1 is in TEST-NET-1 (RFC 5737) and is never assigned to a real
// interface, so binding to it only succeeds with IP_FREEBIND.
const nonLocalAddr = "192.0.2.1:0"

var _ = Describe("freebind Control on linux", func() {
	BeforeEach(func(ctx context.Context) {
		// If the environment already permits non-local binds (e.g. the
		// ip_nonlocal_bind sysctl is enabled), we cannot tell whether
		// IP_FREEBIND is what made the bind succeed, so skip.
		lc := net.ListenConfig{}
		if l, err := lc.Listen(ctx, "tcp", nonLocalAddr); err == nil {
			_ = l.Close()
			Skip("environment permits non-local bind; cannot validate IP_FREEBIND")
		}
	})

	It("binds a non-local TCP address", func(ctx context.Context) {
		lc := net.ListenConfig{Control: freebind.Control}

		l, err := lc.Listen(ctx, "tcp", nonLocalAddr)
		Expect(err).ToNot(HaveOccurred())
		Expect(l.Close()).To(Succeed())
	})

	It("binds a non-local UDP address", func(ctx context.Context) {
		lc := net.ListenConfig{Control: freebind.Control}

		pc, err := lc.ListenPacket(ctx, "udp", nonLocalAddr)
		Expect(err).ToNot(HaveOccurred())
		Expect(pc.Close()).To(Succeed())
	})

	It("reports the platform as supported", func() {
		Expect(freebind.Supported).To(BeTrue())
	})
})
