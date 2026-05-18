package config

import (
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"
)

var _ = Describe("HTTP3Config", func() {
	suiteBeforeEach()

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := HTTP3{}
			Expect(defaults.Set(&cfg)).Should(Succeed())
			Expect(cfg.IsEnabled()).Should(BeFalse())
		})

		When("enabled", func() {
			It("should be true", func() {
				cfg := HTTP3{Enable: true}
				Expect(cfg.IsEnabled()).Should(BeTrue())
			})
		})

		When("disabled", func() {
			It("should be false", func() {
				cfg := HTTP3{Enable: false}
				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log enabled exactly once", func() {
			cfg := HTTP3{Enable: true}
			cfg.LogConfig(logger)

			Expect(hook.Calls).Should(HaveLen(1))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("enabled")))
		})
	})

	Describe("Config integration", func() {
		It("is reachable as Config.HTTP3", func() {
			c := Config{}
			Expect(defaults.Set(&c)).Should(Succeed())

			Expect(c.HTTP3.IsEnabled()).Should(BeFalse())
		})

		It("respects the yaml tag", func() {
			var c Config
			Expect(defaults.Set(&c)).Should(Succeed())

			data := []byte("http3:\n  enable: true\n")
			Expect(yaml.Unmarshal(data, &c)).Should(Succeed())

			Expect(c.HTTP3.IsEnabled()).Should(BeTrue())
		})
	})
})
