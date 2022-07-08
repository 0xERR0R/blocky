//go:build !darwin

package socket

import (
	"errors"
	"net"
)

func LaunchdSockets(address string) ([]int, error) {
	return nil, errors.New("launchd socket activation is only supported on darwin")
}
