package server

import (
	"context"
	"net"
	"net/http"
	"time"
)

type httpServer struct {
	inner http.Server

	name string
}

func newHTTPServer(name string, handler http.Handler) *httpServer {
	const (
		readHeaderTimeout = 20 * time.Second
		readTimeout       = 20 * time.Second
		writeTimeout      = 20 * time.Second
	)

	return &httpServer{
		inner: http.Server{
			ReadTimeout:       readTimeout,
			ReadHeaderTimeout: readHeaderTimeout,
			WriteTimeout:      writeTimeout,

			Handler: handler,
		},

		name: name,
	}
}

func (s *httpServer) String() string {
	return s.name
}

func (s *httpServer) Serve(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()

		s.inner.Close()
	}()

	return s.inner.Serve(l)
}
