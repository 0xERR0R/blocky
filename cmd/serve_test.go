package cmd

import (
	"blocky/config"
	"time"

	. "github.com/onsi/ginkgo"
)

var _ = Describe("Serve command", func() {
	When("Serve command is called", func() {
		It("should start DNS server", func() {
			cfg.BootstrapDNS = config.Upstream{
				Net:  "tcp+udp",
				Host: "1.1.1.1",
				Port: 53,
			}
			go startServer(newServeCommand(), []string{})

			time.Sleep(100 * time.Millisecond)

			done <- true
		})
	})
})
