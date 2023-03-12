package config

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var validDomain = regexp.MustCompile(
	`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)

// Upstream is the definition of external DNS server
type Upstream struct {
	Net        NetProtocol
	Host       string
	Port       uint16
	Path       string
	CommonName string // Common Name to use for certificate verification; optional. "" uses .Host
}

// IsDefault returns true if u is the default value
func (u *Upstream) IsDefault() bool {
	return *u == Upstream{}
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
		sb.WriteString(fmt.Sprint(u.Port))
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
func ParseUpstream(upstream string) (Upstream, error) {
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

	return
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
