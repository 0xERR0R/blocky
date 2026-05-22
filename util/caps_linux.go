//go:build linux

package util

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// RaiseNetBindService promotes CAP_NET_BIND_SERVICE from the process's permitted
// set into its effective set, across all OS threads (via syscall.AllThreadsSyscall,
// which applies the capability change to every thread — this matters because Go's
// net package may run bind() on any thread). It returns whether the capability is
// effective afterwards.
//
// It is best-effort: if the capability is not present in the permitted set
// (e.g. the runtime dropped all capabilities), it makes no change and returns
// (false, nil). Promoting an already-permitted capability to effective needs no
// privilege, so the common path does not fail.
func RaiseNetBindService() (effective bool, err error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData

	if err = unix.Capget(&hdr, &data[0]); err != nil {
		return false, err
	}

	const (
		capNetBindService = unix.CAP_NET_BIND_SERVICE
		capsPerWord       = 32 // each CapUserData word holds 32 capability bits
	)

	// Capabilities 0-31 are in data[0], 32-63 in data[1].
	// CAP_NET_BIND_SERVICE = 10, so it lives in data[0].
	capBit := uint32(1) << (capNetBindService % capsPerWord)
	idx := capNetBindService / capsPerWord

	if data[idx].Permitted&capBit == 0 {
		// Not in permitted set; nothing to raise.
		return false, nil
	}

	if data[idx].Effective&capBit != 0 {
		// Already effective.
		return true, nil
	}

	// Add the cap to the effective set.
	data[idx].Effective |= capBit

	// Apply to all OS threads so any goroutine that calls bind() sees the
	// capability. AllThreadsSyscall requires CGO_ENABLED=0 (it returns ENOTSUP
	// under cgo); Blocky is always built as a pure-Go static binary.
	// The unsafe.Pointer->uintptr conversions are inlined in the call as
	// required by the unsafe.Pointer rules.
	_, _, errno := syscall.AllThreadsSyscall(
		unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
	if errno != 0 {
		return false, errno
	}

	return true, nil
}
