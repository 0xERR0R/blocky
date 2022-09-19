package cmd

import (
	"fmt"

	"github.com/miekg/dns"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Healthcheck command", func() {
	Describe("Call healthcheck command", func() {
		It("should fail", func() {
			c := NewHealthcheckCommand()
			c.SetArgs([]string{"-p", "5344"})

			err := c.Execute()

			Expect(err).Should(HaveOccurred())
		})

		It("shoul succeed", func() {
			srv := createMockServer()
			go func() {
				defer GinkgoRecover()
				err := srv.ListenAndServe()
				Expect(err).Should(Succeed())
			}()
			DeferCleanup(srv.Shutdown)

			Eventually(func() error {
				c := NewHealthcheckCommand()
				c.SetArgs([]string{"-p", "5333"})

				return c.Execute()
			}, "1s").Should(Succeed())
		})
	})
})

func createMockServer() *dns.Server {
	res := &dns.Server{
		Addr:    "127.0.0.1:5333",
		Net:     "tcp",
		Handler: dns.NewServeMux(),
		NotifyStartedFunc: func() {
			fmt.Println("Mock helthcheck server is up")
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

	return res
}
