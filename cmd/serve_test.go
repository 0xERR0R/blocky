package cmd

import (
	"time"

	"github.com/0xERR0R/blocky/config"

	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("Serve command", func() {
	When("Serve command is called", func() {
		It("should start DNS server", func() {
			config.GetConfig().BootstrapDNS = config.BootstrapConfig{
				Upstream: config.Upstream{
					Net:  config.NetProtocolTcpTls,
					Host: "1.1.1.1",
					Port: 53,
				},
			}

			isConfigMandatory = false

			go func() {
				_ = startServer(newServeCommand(), []string{})
			}()

			time.Sleep(100 * time.Millisecond)

			done <- true
		})
	})
})
