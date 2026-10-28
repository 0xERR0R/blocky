package util

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

const (
	IPv4PtrSuffix = ".in-addr.arpa."
	IPv6PtrSuffix = ".ip6.arpa."

	byteBits = 8
)

var ErrInvalidArpaAddrLen = errors.New("arpa hostname is not of expected length")

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
	for _, part := range slices.Backward(parts) {
		p, err := strconv.ParseUint(part, base10, byteBits)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IPv4 octet '%s' in arpa address '%s': %w", part, arpa, err)
		}

		buf = append(buf, byte(p))
	}

	return net.IPv4(buf[0], buf[1], buf[2], buf[3]), nil
}

func parseIPv6FromArpaAddr(arpa string) (net.IP, error) {
	const (
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
		msNibble, err := parseArpaNibble(parts[i], arpa)
		if err != nil {
			return nil, err
		}

		lsNibble, err := parseArpaNibble(parts[i-1], arpa)
		if err != nil {
			return nil, err
		}

		part := msNibble<<nibbleBits | lsNibble

		buf = append(buf, byte(part)) //nolint:gosec // nibble values always fit in a byte
	}

	return net.IP(buf), nil
}

// parseArpaNibble parses a single hexadecimal digit label of an ip6.arpa name.
func parseArpaNibble(part, arpa string) (uint64, error) {
	const (
		base16     = 16
		nibbleBits = byteBits / 2
	)

	if len(part) != 1 {
		return 0, fmt.Errorf("invalid IPv6 nibble '%s' in arpa address '%s': must be a single hex digit", part, arpa)
	}

	nibble, err := strconv.ParseUint(part, base16, nibbleBits)
	if err != nil {
		return 0, fmt.Errorf("failed to parse IPv6 nibble '%s' in arpa address '%s': %w", part, arpa, err)
	}

	return nibble, nil
}
