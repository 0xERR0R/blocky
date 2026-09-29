// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"
)

var _ = Describe("Debug", func() {
	suiteBeforeEach()

	Describe("IsEnabled", func() {
		It("is false by default — the diagnostics listener is opt-in", func() {
			var cfg Debug
			Expect(defaults.Set(&cfg)).Should(Succeed())
			Expect(cfg.IsEnabled()).Should(BeFalse())
			Expect(cfg.Port).Should(Equal(uint16(6060)))
		})

		When("enabled", func() {
			It("is true", func() {
				Expect((&Debug{Enable: true}).IsEnabled()).Should(BeTrue())
			})
		})
	})

	Describe("ListenAddresses", func() {
		It("only ever returns loopback addresses, one per IP family", func() {
			cfg := Debug{Enable: true, Port: 6060}
			Expect(cfg.ListenAddresses()).Should(ConsistOf("127.0.0.1:6060", "[::1]:6060"))
		})
	})

	Describe("LogConfig", func() {
		It("logs the bind addresses", func() {
			cfg := Debug{Enable: true, Port: 6060}
			cfg.LogConfig(logger)

			Expect(hook.Calls).Should(HaveLen(1))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("127.0.0.1:6060")))
		})
	})

	Describe("validate", func() {
		It("accepts the disabled zero value", func() {
			Expect((&Debug{}).validate()).Should(Succeed())
		})

		It("rejects port 0 when enabled", func() {
			err := (&Debug{Enable: true}).validate()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("debug.port"))
		})
	})

	Describe("Config integration", func() {
		It("is reachable as Config.Debug and off by default", func() {
			var c Config
			Expect(defaults.Set(&c)).Should(Succeed())
			Expect(c.Debug.IsEnabled()).Should(BeFalse())
		})

		It("respects the yaml tags", func() {
			var c Config
			Expect(defaults.Set(&c)).Should(Succeed())

			data := []byte("debug:\n  enable: true\n  port: 7070\n")
			Expect(yaml.Unmarshal(data, &c)).Should(Succeed())

			Expect(c.Debug.IsEnabled()).Should(BeTrue())
			Expect(c.Debug.ListenAddresses()).Should(ConsistOf("127.0.0.1:7070", "[::1]:7070"))
		})
	})
})
