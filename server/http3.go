package server

import (
	"crypto/tls"

	"github.com/quic-go/quic-go/http3"
)

// newH3TLSConfig clones base, forces TLS 1.3, and sets the h3 ALPN.
// The base config is not mutated.
func newH3TLSConfig(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	cfg.MinVersion = tls.VersionTLS13

	return http3.ConfigureTLSConfig(cfg)
}
