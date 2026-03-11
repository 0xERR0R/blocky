package resolver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// quicUpstreamClient implements DNS-over-QUIC (RFC 9250) using QUIC transport.
// It maintains a persistent QUIC connection with 0-RTT session resumption support.
type quicUpstreamClient struct {
	tlsConfig *tls.Config

	mu   sync.Mutex
	conn *quic.Conn
}

func (r *quicUpstreamClient) fmtURL(ip net.IP, port uint16, _ string) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

func (r *quicUpstreamClient) callExternal(
	ctx context.Context, msg *dns.Msg, upstreamURL string, _ model.RequestProtocol,
) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	conn, err := r.getConnection(ctx, upstreamURL)
	if err != nil {
		return nil, 0, fmt.Errorf("QUIC connection to %s failed: %w", upstreamURL, err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		// Connection may be stale, reset and retry once
		r.resetConnection()

		conn, err = r.getConnection(ctx, upstreamURL)
		if err != nil {
			return nil, 0, fmt.Errorf("QUIC reconnection to %s failed: %w", upstreamURL, err)
		}

		stream, err = conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("QUIC stream open to %s failed: %w", upstreamURL, err)
		}
	}

	resp, err := r.exchangeDoQ(msg, stream)
	if err != nil {
		return nil, 0, fmt.Errorf("DoQ exchange with %s failed: %w", upstreamURL, err)
	}

	return resp, time.Since(start), nil
}

// exchangeDoQ performs a single DNS-over-QUIC exchange on a QUIC stream.
// Per RFC 9250 Section 4.2: each query is sent on a dedicated stream with
// a 2-byte length prefix followed by the DNS message.
func (r *quicUpstreamClient) exchangeDoQ(msg *dns.Msg, stream *quic.Stream) (*dns.Msg, error) {
	// Pack the DNS message
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("can't pack message: %w", err)
	}

	// Write 2-byte length prefix + DNS message (RFC 9250 Section 4.2)
	buf := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(buf, uint16(len(packed)))
	copy(buf[2:], packed)

	if _, err = stream.Write(buf); err != nil {
		return nil, fmt.Errorf("can't write to QUIC stream: %w", err)
	}

	// Signal that we're done writing (half-close the send side)
	if err = stream.Close(); err != nil {
		return nil, fmt.Errorf("can't close QUIC stream send side: %w", err)
	}

	// Read the response
	respBytes, err := io.ReadAll(stream)
	if err != nil {
		return nil, fmt.Errorf("can't read from QUIC stream: %w", err)
	}

	if len(respBytes) < 2 {
		return nil, fmt.Errorf("DoQ response too short: %d bytes", len(respBytes))
	}

	// Parse 2-byte length prefix
	respLen := binary.BigEndian.Uint16(respBytes[:2])
	if int(respLen) != len(respBytes)-2 {
		return nil, fmt.Errorf("DoQ response length mismatch: header says %d, got %d", respLen, len(respBytes)-2)
	}

	// Unpack the DNS response
	resp := new(dns.Msg)
	if err = resp.Unpack(respBytes[2:]); err != nil {
		return nil, fmt.Errorf("can't unpack response: %w", err)
	}

	return resp, nil
}

// getConnection returns an existing QUIC connection or creates a new one.
// Uses DialAddrEarly for 0-RTT support on reconnection.
func (r *quicUpstreamClient) getConnection(ctx context.Context, addr string) (*quic.Conn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.conn != nil {
		select {
		case <-r.conn.Context().Done():
			// Connection is closed, need a new one
			r.conn = nil
		default:
			return r.conn, nil
		}
	}

	// Clone TLS config and set ALPN for DoQ (RFC 9250 Section 4.3)
	tlsCfg := r.tlsConfig.Clone()
	tlsCfg.NextProtos = []string{"doq"}

	conn, err := quic.DialAddrEarly(ctx, addr, tlsCfg, &quic.Config{
		Allow0RTT: true,
	})
	if err != nil {
		return nil, fmt.Errorf("QUIC dial failed: %w", err)
	}

	r.conn = conn

	return conn, nil
}

func (r *quicUpstreamClient) resetConnection() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.conn != nil {
		r.conn.CloseWithError(0, "")
		r.conn = nil
	}
}
