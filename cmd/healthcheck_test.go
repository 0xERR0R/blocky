package cmd

import (
	"fmt"

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
			hostPort := helpertest.GetHostPort(ip, 65100)
			port := helpertest.GetStringPort(65100)
			srv := createMockServer(hostPort)
			go func() {
				defer GinkgoRecover()
				err := srv.ListenAndServe()
				Expect(err).Should(Succeed())
			}()

			Eventually(func() error {
				c := NewHealthcheckCommand()
				c.SetArgs([]string{"-p", port, "-b", ip})

				return c.Execute()
			}, "1s").Should(Succeed())
		})
	})
})

func createMockServer(hostPort string) *dns.Server {
	res := &dns.Server{
		Addr:    hostPort,
		Net:     "tcp",
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			fmt.Printf("Mock healthcheck server is up: %s\n", hostPort)
		},
	}

	th := res.Handler.(*dns.ServeMux)
	th.HandleFunc("healthcheck.blocky", func(w dns.ResponseWriter, request *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(request)
		resp.Rcode = dns.RcodeSuccess

		err := w.WriteMsg(resp)
		Expect(err).Should(Succeed())
	})

	DeferCleanup(res.Shutdown)

	return res
}
