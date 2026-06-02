//go:build linux

// Package freebind provides a net.ListenConfig.Control hook that sets the Linux
// IP_FREEBIND (and IPV6_FREEBIND) socket option, allowing listeners to bind to
// IP addresses that are not yet assigned to a network interface.
package freebind

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Supported reports whether the freebind Control hook has an effect on this
// platform. It is true on Linux.
const Supported = true

// Control is a net.ListenConfig.Control function that enables binding to
// not-yet-available addresses by setting IP_FREEBIND (IPv4) and IPV6_FREEBIND
// (IPv6) on the socket.
//
// Both options are attempted; depending on the socket's address family one of
// them returns ENOPROTOOPT, which is expected. The call only fails if neither
// option could be set.
func Control(network, address string, c syscall.RawConn) error {
	var sockErr error

	if err := c.Control(func(fd uintptr) {
		errV4 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_FREEBIND, 1)
		errV6 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)

		if errV4 != nil && errV6 != nil {
			sockErr = errV4
		}
	}); err != nil {
		return err
	}

	return sockErr
}
