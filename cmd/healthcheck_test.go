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
			port := helpertest.GetStringPort(5100)
      ip := "127.0.0.1"
			srv := createMockServer(ip, port)
			go func() {
				defer GinkgoRecover()
				err := srv.ListenAndServe()
				Expect(err).Should(Succeed())
			}()

			Eventually(func() error {
				c := NewHealthcheckCommand()
				c.SetArgs([]string{"-p", port})
				c.SetArgs([]string{"--bindip", ip})

				return c.Execute()
			}, "1s").Should(Succeed())
		})
	})
})

func createMockServer(ip string, port string) *dns.Server {
	res := &dns.Server{
		Addr:    ip + ":" + port,
		Net:     "tcp",
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			fmt.Println("Mock healthcheck server is up")
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
