package config

import (
	"time"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HostsFileConfig", func() {
	var (
		cfg HostsFileConfig
	)

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = HostsFileConfig{
			Filepath:       "/dev/null",
			HostsTTL:       Duration(29 * time.Minute),
			RefreshPeriod:  Duration(30 * time.Minute),
			FilterLoopback: true,
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := HostsFileConfig{}
			Expect(defaults.Set(&cfg)).Should(Succeed())

			Expect(cfg.IsEnabled()).Should(BeFalse())
		})

		When("enabled", func() {
			It("should be true", func() {
				Expect(cfg.IsEnabled()).Should(BeTrue())
			})
		})

		When("disabled", func() {
			It("should be false", func() {
				cfg := HostsFileConfig{}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("file path: /dev/null")))
		})
	})
})
