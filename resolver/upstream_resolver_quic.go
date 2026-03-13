package resolver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	// quicMaxIdleTimeout is the maximum time a QUIC connection can be idle before being closed.
	quicMaxIdleTimeout = 30 * time.Second

	// quicKeepAlivePeriod is the interval for sending keep-alive frames to maintain the connection.
	quicKeepAlivePeriod = 15 * time.Second
)

// quicUpstreamClient implements DNS-over-QUIC (RFC 9250) using QUIC transport.
// It maintains a persistent QUIC connection with 0-RTT session resumption support.
type quicUpstreamClient struct {
	tlsConfig  *tls.Config
	quicConfig *quic.Config

	mu   sync.Mutex
	conn *quic.Conn
}

func newQuicUpstreamClient(tlsConfig *tls.Config) *quicUpstreamClient {
	// Set ALPN for DoQ (RFC 9250 Section 4.3)
	tlsConfig.NextProtos = []string{"doq"}

	return &quicUpstreamClient{
		tlsConfig: tlsConfig,
		quicConfig: &quic.Config{
			Allow0RTT:       true,
			MaxIdleTimeout:  quicMaxIdleTimeout,
			KeepAlivePeriod: quicKeepAlivePeriod,
		},
	}
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
		// Connection may be stale, reset and retry once.
		// resetConnection is safe against races: it only closes the specific
		// connection we got, so concurrent goroutines won't double-reset.
		r.resetConnection(conn)

		conn, err = r.getConnection(ctx, upstreamURL)
		if err != nil {
			return nil, 0, fmt.Errorf("QUIC reconnection to %s failed: %w", upstreamURL, err)
		}

		stream, err = conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("QUIC stream open to %s failed: %w", upstreamURL, err)
		}
	}

	// Ensure the stream read side is cancelled on any failure path
	defer stream.CancelRead(0)

	resp, err := r.exchangeDoQ(ctx, msg, stream)
	if err != nil {
		return nil, 0, fmt.Errorf("DoQ exchange with %s failed: %w", upstreamURL, err)
	}

	return resp, time.Since(start), nil
}

// exchangeDoQ performs a single DNS-over-QUIC exchange on a QUIC stream.
// Per RFC 9250 Section 4.2: each query is sent on a dedicated stream with
// a 2-byte length prefix followed by the DNS message. The message ID MUST
// be set to 0 for security (preventing correlation attacks).
func (r *quicUpstreamClient) exchangeDoQ(
	ctx context.Context, msg *dns.Msg, stream *quic.Stream,
) (*dns.Msg, error) {
	// Set stream deadline from context to prevent indefinite blocking
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("can't set stream deadline: %w", err)
		}
	}

	// RFC 9250 Section 4.2: The DNS Message ID MUST be set to 0.
	originalID := msg.Id
	msg.Id = 0

	packed, err := msg.Pack()

	// Restore original ID regardless of pack result
	msg.Id = originalID

	if err != nil {
		return nil, fmt.Errorf("can't pack message: %w", err)
	}

	if len(packed) > math.MaxUint16 {
		return nil, fmt.Errorf("DNS message too large for DoQ: %d bytes", len(packed))
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

	// Read 2-byte length prefix first, then exact response bytes
	var lenBuf [2]byte
	if _, err = io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("can't read DoQ response length: %w", err)
	}

	respLen := binary.BigEndian.Uint16(lenBuf[:])

	respBuf := make([]byte, respLen)
	if _, err = io.ReadFull(stream, respBuf); err != nil {
		return nil, fmt.Errorf("can't read DoQ response body: %w", err)
	}

	resp := new(dns.Msg)
	if err = resp.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("can't unpack response: %w", err)
	}

	// Restore the original message ID in the response
	resp.Id = originalID

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

	conn, err := quic.DialAddrEarly(ctx, addr, r.tlsConfig, r.quicConfig)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial failed: %w", err)
	}

	r.conn = conn

	return conn, nil
}

// resetConnection closes the given stale connection only if it is still the active one.
// This prevents races where multiple goroutines reset different connections.
func (r *quicUpstreamClient) resetConnection(stale *quic.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.conn == stale {
		_ = r.conn.CloseWithError(0, "")
		r.conn = nil
	}
}
