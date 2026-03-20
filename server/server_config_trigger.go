//go:build !windows

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
		defer signal.Stop(signals)

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

func registerReloadTrigger(ctx context.Context, s *Server) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)

	go func() {
		defer signal.Stop(signals)

		for {
			select {
			case <-signals:
				logger().Info("SIGHUP received, triggering config reload")
				if err := s.Reload(); err != nil { //nolint:contextcheck
					logger().Errorf("SIGHUP reload failed: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}
