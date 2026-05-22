//go:build !linux

package util

// RaiseNetBindService is a no-op on platforms without Linux capabilities. It
// reports effective == true so that callers do not emit a privileged-port
// capability warning for a concept that does not apply on this platform.
func RaiseNetBindService() (effective bool, err error) {
	return true, nil
}
