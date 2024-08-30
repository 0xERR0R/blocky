package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
)

// Listener is a net.Listener that provides information about
// what protocol and address it is configured for.
type Listener interface {
	fmt.Stringer
	net.Listener

	// Exposes returns the endpoint for this listener.
	//
	// It can be used to find service(s) with matching configuration.
	Exposes() Endpoint
}

// ListenerInfo can be embedded in structs to help implement Listener.
type ListenerInfo struct {
	Endpoint
}

func (i *ListenerInfo) Exposes() Endpoint { return i.Endpoint }

// NetListener implements Listener using an existing net.Listener.
type NetListener struct {
	net.Listener
	ListenerInfo
}

func NewNetListener(endpoint Endpoint, inner net.Listener) *NetListener {
	return &NetListener{
		Listener:     inner,
		ListenerInfo: ListenerInfo{endpoint},
	}
}

// TCPListener is a Listener for a TCP socket.
type TCPListener struct{ NetListener }

// ListenTCP creates a new TCPListener.
func ListenTCP(ctx context.Context, endpoint Endpoint) (*TCPListener, error) {
	var lc net.ListenConfig

	l, err := lc.Listen(ctx, "tcp", endpoint.AddrConf)
	if err != nil {
		return nil, err // err already has all the info we could add
	}

	inner := NewNetListener(endpoint, l)

	return &TCPListener{*inner}, nil
}

// TLSListener is a Listener using TLS over TCP.
type TLSListener struct{ NetListener }

// ListenTLS creates a new TLSListener.
func ListenTLS(ctx context.Context, endpoint Endpoint, cfg *tls.Config) (*TLSListener, error) {
	tcp, err := ListenTCP(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	inner := tcp.NetListener

	inner.Listener = tls.NewListener(inner.Listener, cfg)

	return &TLSListener{inner}, nil
}
