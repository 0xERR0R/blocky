// +build !windows

package resolver

import (
	"os"
	"os/signal"
	"syscall"
)

func registerStatsTrigger(resolver *StatsResolver) {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGUSR2)

	go func() {
		for {
			<-signals
			resolver.printStats()
		}
	}()
}
