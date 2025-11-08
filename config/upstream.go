package config

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/jedisct1/go-dnsstamps"
)

var validDomain = regexp.MustCompile(
	`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)

// CertificateFingerprint represents a SHA256 fingerprint of a TLS certificate (32 bytes)
type CertificateFingerprint []byte

// Upstream is the definition of external DNS server
type Upstream struct {
	Net        NetProtocol
	Host       string
	Port       uint16
	Path       string
	CommonName string // Common Name to use for certificate verification; optional. "" uses .Host

	// DNS stamp metadata (optional) - only populated when parsing DNS stamps
	CertificateFingerprints []CertificateFingerprint // SHA256 fingerprints for TLS certificate pinning
}

// IsDefault returns true if u is the default value
func (u *Upstream) IsDefault() bool {
	return u.Net == 0 && u.Host == "" && u.Port == 0 && u.Path == "" &&
		u.CommonName == "" && len(u.CertificateFingerprints) == 0
}

// String returns the string representation of u
func (u Upstream) String() string {
	if u.IsDefault() {
		return "no upstream"
	}

	var sb strings.Builder

	sb.WriteString(u.Net.String())
	sb.WriteRune(':')

	if u.Net == NetProtocolHttps {
		sb.WriteString("//")
	}

	isIPv6 := strings.ContainsRune(u.Host, ':')
	if isIPv6 {
		sb.WriteRune('[')
		sb.WriteString(u.Host)
		sb.WriteRune(']')
	} else {
		sb.WriteString(u.Host)
	}

	if u.Port != netDefaultPort[u.Net] {
		sb.WriteRune(':')
		sb.WriteString(strconv.FormatUint(uint64(u.Port), 10))
	}

	if u.Path != "" {
		sb.WriteString(u.Path)
	}

	return sb.String()
}

// UnmarshalText implements `encoding.TextUnmarshaler`.
func (u *Upstream) UnmarshalText(data []byte) error {
	s := string(data)

	upstream, err := ParseUpstream(s)
	if err != nil {
		return fmt.Errorf("can't convert upstream '%s': %w", s, err)
	}

	*u = upstream

	return nil
}

// ParseUpstream creates new Upstream from passed string in format [net]:host[:port][/path][#commonname]
// or DNS Stamp format: sdns://...
func ParseUpstream(upstream string) (Upstream, error) {
	// Check if it's a DNS stamp
	if isDNSStamp(upstream) {
		return parseStamp(upstream)
	}

	// Existing parsing logic for traditional format
	var path string

	var port uint16

	commonName, upstream := extractCommonName(upstream)

	n, upstream := extractNet(upstream)

	path, upstream = extractPath(upstream)

	host, portString, err := net.SplitHostPort(upstream)

	// string contains host:port
	if err == nil {
		p, err := ConvertPort(portString)
		if err != nil {
			err = fmt.Errorf("can't convert port to number (1 - 65535) %w", err)

			return Upstream{}, err
		}

		port = p
	} else {
		// only host, use default port
		host = upstream
		port = netDefaultPort[n]

		// trim any IPv6 brackets
		host = strings.TrimPrefix(host, "[")
		host = strings.TrimSuffix(host, "]")
	}

	// validate hostname or ip
	if ip := net.ParseIP(host); ip == nil {
		// is not IP
		if !validDomain.MatchString(host) {
			return Upstream{}, fmt.Errorf("wrong host name '%s'", host)
		}
	}

	return Upstream{
		Net:        n,
		Host:       host,
		Port:       port,
		Path:       path,
		CommonName: commonName,
	}, nil
}

func extractCommonName(in string) (string, string) {
	upstream, cn, _ := strings.Cut(in, "#")

	return cn, upstream
}

func extractPath(in string) (path, upstream string) {
	slashIdx := strings.Index(in, "/")

	if slashIdx >= 0 {
		path = in[slashIdx:]
		upstream = in[:slashIdx]
	} else {
		upstream = in
	}

	return path, upstream
}

func extractNet(upstream string) (NetProtocol, string) {
	tcpUDPPrefix := NetProtocolTcpUdp.String() + ":"
	if strings.HasPrefix(upstream, tcpUDPPrefix) {
		return NetProtocolTcpUdp, upstream[len(tcpUDPPrefix):]
	}

	tcpTLSPrefix := NetProtocolTcpTls.String() + ":"
	if strings.HasPrefix(upstream, tcpTLSPrefix) {
		return NetProtocolTcpTls, upstream[len(tcpTLSPrefix):]
	}

	httpsPrefix := NetProtocolHttps.String() + ":"
	if strings.HasPrefix(upstream, httpsPrefix) {
		return NetProtocolHttps, strings.TrimPrefix(upstream[len(httpsPrefix):], "//")
	}

	return NetProtocolTcpUdp, upstream
}

// isDNSStamp checks if a string is a DNS stamp format
func isDNSStamp(s string) bool {
	return strings.HasPrefix(s, "sdns://")
}

// parseStamp parses a DNS stamp and converts it to an Upstream
func parseStamp(stampStr string) (Upstream, error) {
	stamp, err := dnsstamps.NewServerStampFromString(stampStr)
	if err != nil {
		return Upstream{}, fmt.Errorf("invalid DNS stamp: %w", err)
	}

	// Map stamp protocol to NetProtocol
	netProto, err := stampProtoToNetProtocol(stamp.Proto)
	if err != nil {
		return Upstream{}, err
	}

	// Extract host and port from ServerAddrStr
	host, port, err := extractStampHostPort(stamp.ServerAddrStr, netProto)
	if err != nil {
		return Upstream{}, err
	}

	// Use provider name as hostname if available (for DoH/DoT)
	hostname := host
	if stamp.ProviderName != "" {
		// Validate provider name is a valid hostname or IP
		if ip := net.ParseIP(stamp.ProviderName); ip == nil {
			// Not an IP, must be a valid hostname
			if !validDomain.MatchString(stamp.ProviderName) {
				return Upstream{}, fmt.Errorf("invalid provider name in DNS stamp: '%s'", stamp.ProviderName)
			}
		}

		hostname = stamp.ProviderName
	}

	// Convert stamp hashes to CertificateFingerprint type
	certFingerprints := make([]CertificateFingerprint, 0, len(stamp.Hashes))
	for _, hash := range stamp.Hashes {
		certFingerprints = append(certFingerprints, CertificateFingerprint(hash))
	}

	upstream := Upstream{
		Net:                     netProto,
		Host:                    hostname,
		Port:                    port,
		Path:                    stamp.Path,
		CommonName:              stamp.ProviderName, // Use provider name for TLS verification
		CertificateFingerprints: certFingerprints,   // SHA256 fingerprints for certificate pinning
	}

	return upstream, nil
}

// extractStampHostPort extracts host and port from a DNS stamp server address string
func extractStampHostPort(serverAddr string, netProto NetProtocol) (string, uint16, error) {
	if serverAddr == "" {
		return "", netDefaultPort[netProto], nil
	}

	h, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		// SplitHostPort failed - could be missing port or raw IP/hostname
		// This is not an error for our purposes, just means no port specified
		// Strip IPv6 brackets if present (e.g., "[2001:db8::1]" -> "2001:db8::1")
		host := serverAddr
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}

		return host, netDefaultPort[netProto], nil
	}

	// Successfully split host and port
	if portStr != "" {
		p, err := ConvertPort(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port in stamp: %w", err)
		}

		return h, p, nil
	}

	return h, netDefaultPort[netProto], nil
}

// stampProtoToNetProtocol maps DNS stamp protocol to Blocky's NetProtocol
func stampProtoToNetProtocol(proto dnsstamps.StampProtoType) (NetProtocol, error) {
	switch proto {
	case dnsstamps.StampProtoTypePlain:
		return NetProtocolTcpUdp, nil
	case dnsstamps.StampProtoTypeDoH:
		return NetProtocolHttps, nil
	case dnsstamps.StampProtoTypeTLS:
		return NetProtocolTcpTls, nil
	case dnsstamps.StampProtoTypeDNSCrypt:
		return NetProtocol(0), errors.New("DNSCrypt protocol not supported")
	case dnsstamps.StampProtoTypeDoQ:
		return NetProtocol(0), errors.New("DNS-over-QUIC protocol not supported")
	case dnsstamps.StampProtoTypeODoHTarget:
		return NetProtocol(0), errors.New("oblivious DoH target not supported")
	case dnsstamps.StampProtoTypeDNSCryptRelay:
		return NetProtocol(0), errors.New("DNSCrypt Relay not supported")
	case dnsstamps.StampProtoTypeODoHRelay:
		return NetProtocol(0), errors.New("ODoH Relay not supported")
	default:
		return NetProtocol(0), fmt.Errorf("unsupported DNS stamp protocol: %v", proto)
	}
}
