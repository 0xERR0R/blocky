// +build !windows

package server

import (
	"os"
	"os/signal"
	"syscall"
)

func registerPrintConfigurationTrigger(s *Server) {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGUSR1)

	go func() {
		for {
			<-signals
			s.printConfiguration()
		}
	}()
}
