//go:build !linux

// Package freebind provides a net.ListenConfig.Control hook that sets the Linux
// IP_FREEBIND (and IPV6_FREEBIND) socket option, allowing listeners to bind to
// IP addresses that are not yet assigned to a network interface.
//
// IP_FREEBIND is Linux-specific; on other platforms this package is a no-op.
package freebind

import "syscall"

// Supported reports whether the freebind Control hook has an effect on this
// platform. It is false on non-Linux platforms.
const Supported = false

// Control is nil on platforms without IP_FREEBIND; a nil net.ListenConfig.Control
// means the listener is created with default behaviour.
var Control func(network, address string, c syscall.RawConn) error
