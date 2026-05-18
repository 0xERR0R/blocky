package server

import (
	"crypto/tls"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

// newH3TLSConfig clones base, forces TLS 1.3, and sets the h3 ALPN.
// The base config is not mutated.
func newH3TLSConfig(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	cfg.MinVersion = tls.VersionTLS13

	return http3.ConfigureTLSConfig(cfg)
}

// http3Server is a thin wrapper around quic-go's http3.Server.
//
// Asymmetric with httpServer: there are N httpServers (one per TCP
// listener) but a single http3Server shared across all UDP listeners.
// The serve loop and shutdown watcher therefore live in Server.Start
// rather than on this wrapper. The wrapper exists for String() (log
// consistency) and as a handle for newAltSvcMiddleware.
type http3Server struct {
	inner http3.Server
	name  string
}

func newHTTP3Server(handler http.Handler, tlsCfg *tls.Config) *http3Server {
	return &http3Server{
		inner: http3.Server{
			TLSConfig: tlsCfg,
			Handler:   withCommonMiddleware(handler),
		},
		name: "http3",
	}
}

func (s *http3Server) String() string { return s.name }
