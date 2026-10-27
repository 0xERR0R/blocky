package config

import (
	"net"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ResponseCompressionConfig", func() {
	var cfg ResponseCompression

	BeforeEach(func() {
		cfg = ResponseCompression{}
	})

	Describe("IsEnabled", func() {
		It("is false by default", func() {
			Expect(cfg.IsEnabled()).Should(BeFalse())
		})

		It("is true when always is set", func() {
			cfg.Always = true
			Expect(cfg.IsEnabled()).Should(BeTrue())
		})

		It("is true when clients are configured", func() {
			cfg.Clients = []string{"192.168.178.10"}
			Expect(cfg.IsEnabled()).Should(BeTrue())
		})
	})

	Describe("LogConfig", func() {
		It("logs the configuration", func() {
			logger, hook := log.NewMockEntry()

			cfg.Clients = []string{"192.168.178.10"}
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("192.168.178.10")))
		})
	})

	Describe("validate", func() {
		It("accepts IPs, CIDRs and client names", func() {
			cfg.Clients = []string{"192.168.178.10", "10.0.0.0/8", "2001:db8::/32", "scale*", "printer"}
			Expect(cfg.validate()).Should(Succeed())
		})

		It("rejects empty entries", func() {
			cfg.Clients = []string{"192.168.178.10", " "}
			Expect(cfg.validate()).ShouldNot(Succeed())
		})
	})

	Describe("ForceFor", func() {
		It("is false by default", func() {
			Expect(cfg.validate()).Should(Succeed())
			Expect(cfg.ForceFor(net.ParseIP("192.168.178.10"), []string{"scale"})).Should(BeFalse())
		})

		When("always is set", func() {
			It("is true for every client", func() {
				cfg.Always = true
				Expect(cfg.validate()).Should(Succeed())

				Expect(cfg.ForceFor(net.ParseIP("192.168.178.10"), nil)).Should(BeTrue())
				Expect(cfg.ForceFor(nil, nil)).Should(BeTrue())
			})
		})

		When("clients are configured", func() {
			BeforeEach(func() {
				cfg.Clients = []string{"192.168.178.10", "10.0.0.0/8", "2001:db8::/32", "Scale*", "printer"}
				Expect(cfg.validate()).Should(Succeed())
			})

			It("matches a configured IP", func() {
				Expect(cfg.ForceFor(net.ParseIP("192.168.178.10"), nil)).Should(BeTrue())
			})

			It("matches IPs within a configured CIDR", func() {
				Expect(cfg.ForceFor(net.ParseIP("10.1.2.3"), nil)).Should(BeTrue())
				Expect(cfg.ForceFor(net.ParseIP("2001:db8::1"), nil)).Should(BeTrue())
			})

			It("matches client names exactly and by wildcard, ignoring case", func() {
				Expect(cfg.ForceFor(net.ParseIP("192.168.178.99"), []string{"printer"})).Should(BeTrue())
				Expect(cfg.ForceFor(net.ParseIP("192.168.178.99"), []string{"other", "scale-bathroom"})).
					Should(BeTrue())
				Expect(cfg.ForceFor(net.ParseIP("192.168.178.99"), []string{"SCALE"})).Should(BeTrue())
			})

			It("doesn't match other clients", func() {
				Expect(cfg.ForceFor(net.ParseIP("192.168.178.99"), []string{"laptop"})).Should(BeFalse())
				Expect(cfg.ForceFor(net.ParseIP("192.168.178.99"), []string{"printer2"})).Should(BeFalse())
				Expect(cfg.ForceFor(nil, nil)).Should(BeFalse())
			})

			It("treats an IP identifier as an IP, not as a client name", func() {
				Expect(cfg.ForceFor(net.ParseIP("192.168.178.99"), []string{"192.168.178.10"})).Should(BeFalse())
			})
		})
	})
})
