package config

import (
	"encoding/base64"
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
	IPs                     []net.IP                 // IPs from the DNS stamp (addr + bootstrap IPs) for bootstrapping
}

// IsDefault returns true if u is the default value
func (u *Upstream) IsDefault() bool {
	return u.Net == 0 && u.Host == "" && u.Port == 0 && u.Path == "" &&
		u.CommonName == "" && len(u.CertificateFingerprints) == 0 && len(u.IPs) == 0
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

// stripPrefix removes the prefix from s if present, returns the remainder and true if removed
func stripPrefix(s, prefix string) (string, bool) {
	if strings.HasPrefix(s, prefix) {
		return s[len(prefix):], true
	}

	return s, false
}

func extractNet(upstream string) (NetProtocol, string) {
	if rest, ok := stripPrefix(upstream, NetProtocolTcpUdp.String()+":"); ok {
		return NetProtocolTcpUdp, rest
	}

	if rest, ok := stripPrefix(upstream, NetProtocolTcpTls.String()+":"); ok {
		return NetProtocolTcpTls, rest
	}

	if rest, ok := stripPrefix(upstream, NetProtocolHttps.String()+":"); ok {
		return NetProtocolHttps, strings.TrimPrefix(rest, "//")
	}

	// Accept both "quic:" and "quic://" for compatibility with other tools (e.g. AdGuard)
	if rest, ok := stripPrefix(upstream, NetProtocolQuic.String()+":"); ok {
		return NetProtocolQuic, strings.TrimPrefix(rest, "//")
	}

	return NetProtocolTcpUdp, upstream
}

// isDNSStamp checks if a string is a DNS stamp format
func isDNSStamp(s string) bool {
	return strings.HasPrefix(s, "sdns://")
}

// parseStamp parses a DNS stamp and converts it to an Upstream
func parseStamp(stampStr string) (Upstream, error) {
	stamp, err := parseServerStamp(stampStr)
	if err != nil {
		return Upstream{}, fmt.Errorf("invalid DNS stamp: %w", err)
	}

	// Map stamp protocol to NetProtocol
	netProto, err := stampProtoToNetProtocol(stamp.Proto)
	if err != nil {
		return Upstream{}, err
	}

	// The addr field carries the server IP literal (per spec it is an IP and may
	// be empty); it is used for bootstrapping. It may also hold a legacy port.
	addrHost, addrPort := splitStampHostPort(stamp.ServerAddrStr)

	// Per draft-denis-dns-stamps the optional port lives on the hostname
	// (ProviderName) field. Fall back to a port on addr for plain/legacy stamps,
	// then to the protocol default.
	hostname, hostnamePort := splitStampHostPort(stamp.ProviderName)

	port, err := stampPort(netProto, hostnamePort, addrPort)
	if err != nil {
		return Upstream{}, err
	}

	// Host/SNI: prefer the (port-stripped) hostname, else the server IP from addr.
	host := hostname
	if host == "" {
		host = addrHost
	}

	if hostname != "" {
		// Validate provider name is a valid hostname or IP
		if ip := net.ParseIP(hostname); ip == nil {
			// Not an IP, must be a valid hostname
			if !validDomain.MatchString(hostname) {
				return Upstream{}, fmt.Errorf("invalid provider name in DNS stamp: '%s'", hostname)
			}
		}
	}

	// Convert stamp hashes to CertificateFingerprint type
	certFingerprints := make([]CertificateFingerprint, 0, len(stamp.Hashes))
	for _, hash := range stamp.Hashes {
		certFingerprints = append(certFingerprints, CertificateFingerprint(hash))
	}

	upstream := Upstream{
		Net:                     netProto,
		Host:                    host,
		Port:                    port,
		Path:                    stamp.Path,
		CommonName:              hostname, // provider name for TLS verification, without any port
		CertificateFingerprints: certFingerprints,
		IPs:                     stampBootstrapIPs(addrHost, stamp.BootstrapIPs),
	}

	return upstream, nil
}

// parseServerStamp parses a DNS stamp, tolerating legacy stamps that encode the
// optional port on the addr field instead of the hostname field, which current
// go-dnsstamps rejects per draft-denis-dns-stamps. We move the port off the addr
// field on the wire and re-parse; if that succeeds, the port location was the only
// defect. We then return the freshly parsed probe stamp (guaranteed fully
// populated because its parse succeeded, rather than relying on the field state of
// the stamp returned alongside the original error) with the original addr restored
// so port resolution still sees the port. A stamp with any other defect still
// fails the re-parse.
func parseServerStamp(stampStr string) (dnsstamps.ServerStamp, error) {
	stamp, err := dnsstamps.NewServerStampFromString(stampStr)
	if err == nil {
		return stamp, nil
	}

	if probeStr, addr, ok := stampWithoutAddrPort(stampStr); ok {
		if probe, probeErr := dnsstamps.NewServerStampFromString(probeStr); probeErr == nil {
			probe.ServerAddrStr = addr // restore the legacy addr:port for port resolution

			return probe, nil
		}
	}

	return stamp, err
}

// stampWithoutAddrPort rewrites a stamp so the addr field drops an optional port.
// It returns the rewritten stamp, the original addr field (including the port),
// and whether a port was actually removed. Only protocols that carry an addr field
// are considered.
func stampWithoutAddrPort(stampStr string) (string, string, bool) {
	const (
		scheme     = "sdns://"
		addrLenPos = 9 // 1 protocol byte + 8 properties bytes
	)

	bin, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(stampStr, scheme))
	if err != nil || len(bin) <= addrLenPos {
		return "", "", false
	}

	if !protoHasAddrField(dnsstamps.StampProtoType(bin[0])) {
		return "", "", false
	}

	addrStart := addrLenPos + 1
	addrEnd := addrStart + int(bin[addrLenPos])

	if addrEnd > len(bin) {
		return "", "", false
	}

	addr := string(bin[addrStart:addrEnd])

	host, _, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) == nil {
		return "", "", false
	}

	if strings.ContainsRune(host, ':') {
		host = "[" + host + "]" // re-bracket IPv6 literal
	}

	out := make([]byte, 0, len(bin))
	out = append(out, bin[:addrLenPos]...)
	out = append(out, byte(len(host)))
	out = append(out, host...)
	out = append(out, bin[addrEnd:]...)

	return scheme + base64.RawURLEncoding.EncodeToString(out), addr, true
}

// protoHasAddrField reports whether a stamp protocol carries an addr field
// (located right after the 8-byte properties block).
func protoHasAddrField(p dnsstamps.StampProtoType) bool {
	switch p {
	case dnsstamps.StampProtoTypeDoH, dnsstamps.StampProtoTypeTLS,
		dnsstamps.StampProtoTypeDoQ, dnsstamps.StampProtoTypeODoHRelay:
		return true
	case dnsstamps.StampProtoTypePlain, dnsstamps.StampProtoTypeDNSCrypt,
		dnsstamps.StampProtoTypeODoHTarget, dnsstamps.StampProtoTypeDNSCryptRelay:
		return false
	default:
		return false
	}
}

// splitStampHostPort splits a stamp "host:port" value into host and port. The
// port is optional; IPv6 brackets are stripped from the host.
func splitStampHostPort(s string) (host, port string) {
	if s == "" {
		return "", ""
	}

	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}

	// No port present; strip IPv6 brackets if any.
	host = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")

	return host, ""
}

// stampPort resolves the upstream port, preferring the port on the hostname
// field, then a legacy port on the addr field, then the protocol default.
func stampPort(netProto NetProtocol, hostnamePort, addrPort string) (uint16, error) {
	portStr := hostnamePort
	if portStr == "" {
		portStr = addrPort
	}

	if portStr == "" {
		return netDefaultPort[netProto], nil
	}

	port, err := ConvertPort(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port in DNS stamp: %w", err)
	}

	return port, nil
}

// stampBootstrapIPs collects the IPs usable for bootstrapping: the server IP
// from the addr field plus the stamp's optional bootstrap IPs, de-duplicated
// while preserving order.
func stampBootstrapIPs(serverIP string, bootstrapIPs []string) []net.IP {
	var ips []net.IP

	seen := make(map[string]struct{}, 1+len(bootstrapIPs))

	add := func(s string) {
		ip := net.ParseIP(s)
		if ip == nil {
			return
		}

		key := ip.String()
		if _, ok := seen[key]; ok {
			return
		}

		seen[key] = struct{}{}
		ips = append(ips, ip)
	}

	add(serverIP)

	for _, s := range bootstrapIPs {
		add(s)
	}

	return ips
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
		return NetProtocolQuic, nil
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
