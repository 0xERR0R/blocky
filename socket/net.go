package socket

import "strings"

func ParseAddress(input string) (address, network string) {
	if strings.HasPrefix(input, "launchd:") {
		address = input[8:]
		network = "launchd"
		return
	}

	address = input
	network = ""

	return
}
