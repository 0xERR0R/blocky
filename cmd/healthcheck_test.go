package cmd

import (
	"fmt"
	"strconv"

	"github.com/0xERR0R/blocky/helpertest"
	"github.com/miekg/dns"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Healthcheck command", func() {
	Describe("Call healthcheck command", func() {
		It("should fail", func() {
			c := NewHealthcheckCommand()
			c.SetArgs([]string{"-p", "533"})

			err := c.Execute()

			Expect(err).Should(HaveOccurred())
		})

		It("should fail", func() {
			c := NewHealthcheckCommand()
			c.SetArgs([]string{"-b", "127.0.2.9"})

			err := c.Execute()

			Expect(err).Should(HaveOccurred())
		})

		It("should succeed", func() {
			ip := "127.0.0.1"
			p := helpertest.NextFreePort()
			hostPort := helpertest.HostPort(ip, p)
			port := strconv.Itoa(p)
			startMockServer(hostPort)

			Eventually(func() error {
				c := NewHealthcheckCommand()
				c.SetArgs([]string{"-p", port, "-b", ip})

				return c.Execute()
			}, "1s").Should(Succeed())
		})
	})
})

// startMockServer brings up a DNS listener on hostPort and blocks until it is
// accepting, so a failed bind fails the spec that asked for the server instead
// of surfacing later as a healthcheck timeout.
//
// It replaces a bare `go srv.ListenAndServe()` per spec: those goroutines were
// never shut down, so each one held its port for the rest of the suite process
// and asserted from a goroutine whose spec had already finished.
func startMockServer(hostPort string) {
	started := make(chan struct{})

	srv := &dns.Server{
		Addr:              hostPort,
		Net:               "tcp",
		Handler:           dns.NewServeMux(),
		NotifyStartedFunc: func() { close(started) },
	}

	srv.Handler.(*dns.ServeMux).HandleFunc("healthcheck.blocky", func(w dns.ResponseWriter, request *dns.Msg) {
		defer GinkgoRecover()

		resp := new(dns.Msg)
		resp.SetReply(request)
		resp.Rcode = dns.RcodeSuccess

		Expect(w.WriteMsg(resp)).Should(Succeed())
	})

	errChan := make(chan error, 1)

	go func() {
		defer GinkgoRecover()
		errChan <- srv.ListenAndServe()
	}()

	DeferCleanup(srv.Shutdown)

	Eventually(started, "2s").Should(BeClosed(), func() string {
		select {
		case err := <-errChan:
			return fmt.Sprintf("mock DNS server on %s never started: %v", hostPort, err)
		default:
			return fmt.Sprintf("mock DNS server on %s never started", hostPort)
		}
	})
}
