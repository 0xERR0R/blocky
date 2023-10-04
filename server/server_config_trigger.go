//go:build !windows
// +build !windows

package server

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func registerPrintConfigurationTrigger(ctx context.Context, s *Server) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)

	go func() {
		for {
			select {
			case <-signals:
				s.printConfiguration()

			case <-ctx.Done():
				return
			}
		}
	}()
}
