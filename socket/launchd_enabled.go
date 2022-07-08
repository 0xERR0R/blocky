//go:build darwin
package socket

/*
#include <stdlib.h>
#include <launch.h>
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"unsafe"
)

func LaunchdSockets(address string) ([]int, error) {
	c_name := C.CString(address)
	var c_fds *C.int
	c_cnt := C.size_t(0)

	err := C.launch_activate_socket(c_name, &c_fds, &c_cnt)
	if err != 0 {
		return nil, fmt.Errorf("couldn't activate launchd socket: %v", err)
	}

	length := int(c_cnt)
	if length < 2 {
		return nil, fmt.Errorf("expected at least two sockets to be configured in launchd for '%s', found %d", address, length)
	}
	ptr := unsafe.Pointer(c_fds)
	defer C.free(ptr)

	fds := (*[1 << 30]C.int)(ptr)[:length:length]
	res := make([]int, length)
	for i := 0; i < length; i++ {
		res[i] = int(fds[i])
	}

	return res, nil
}

func BuildPacketConn(fd int) (net.PacketConn, error) {
	file := os.NewFile(uintptr(fd), "")

	return net.FilePacketConn(file)
}

func BuildListener(fd int) (net.Listener, error) {
	file := os.NewFile(uintptr(fd), "")

	return net.FileListener(file)
}
