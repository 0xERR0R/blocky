package util

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	IPv4PtrSuffix = ".in-addr.arpa."
	IPv6PtrSuffix = ".ip6.arpa."

	byteBits = 8
)

var (
	ErrInvalidArpaAddrLen = errors.New("arpa hostname is not of expected length")
)

func ParseIPFromArpaAddr(arpa string) (net.IP, error) {
	if strings.HasSuffix(arpa, IPv4PtrSuffix) {
		return parseIPv4FromArpaAddr(arpa)
	}

	if strings.HasSuffix(arpa, IPv6PtrSuffix) {
		return parseIPv6FromArpaAddr(arpa)
	}

	return nil, fmt.Errorf("invalid arpa hostname: %s", arpa)
}

func parseIPv4FromArpaAddr(arpa string) (net.IP, error) {
	const base10 = 10

	revAddr := strings.TrimSuffix(arpa, IPv4PtrSuffix)

	parts := strings.Split(revAddr, ".")
	if len(parts) != net.IPv4len {
		return nil, ErrInvalidArpaAddrLen
	}

	buf := make([]byte, 0, net.IPv4len)

	// Parse and add each byte, in reverse, to the buffer
	for i := len(parts) - 1; i >= 0; i-- {
		part, err := strconv.ParseUint(parts[i], base10, byteBits)
		if err != nil {
			return nil, err
		}

		buf = append(buf, byte(part))
	}

	return net.IPv4(buf[0], buf[1], buf[2], buf[3]), nil
}

func parseIPv6FromArpaAddr(arpa string) (net.IP, error) {
	const (
		base16     = 16
		ipv6Bytes  = 2 * net.IPv6len
		nibbleBits = byteBits / 2
	)

	revAddr := strings.TrimSuffix(arpa, IPv6PtrSuffix)

	parts := strings.Split(revAddr, ".")
	if len(parts) != ipv6Bytes {
		return nil, ErrInvalidArpaAddrLen
	}

	buf := make([]byte, 0, net.IPv6len)

	// Parse and add each byte, in reverse, to the buffer
	for i := len(parts) - 1; i >= 0; i -= 2 {
		msNibble, err := strconv.ParseUint(parts[i], base16, byteBits)
		if err != nil {
			return nil, err
		}

		lsNibble, err := strconv.ParseUint(parts[i-1], base16, byteBits)
		if err != nil {
			return nil, err
		}

		part := msNibble<<nibbleBits | lsNibble

		buf = append(buf, byte(part))
	}

	return net.IP(buf), nil
}
