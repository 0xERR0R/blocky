package cmd

import (
	"time"

	"github.com/0xERR0R/blocky/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

			go func(doneChannel chan bool) {
				defer GinkgoRecover()

				time.Sleep(200 * time.Millisecond)

				doneChannel <- true
			}(done)

			err := startServer(newServeCommand(), []string{})
			Expect(err).Should(HaveOccurred())
		})
	})
})
