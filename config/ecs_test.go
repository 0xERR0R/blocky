package config

import (
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("EcsConfig", func() {
	var c EcsConfig
	BeforeEach(func() {
		err := defaults.Set(&c)
		Expect(err).Should(Succeed())
	})
	Describe("validate config", func() {
		When("IPv4Mask is invalid", func() {
			BeforeEach(func() {
				c.IPv4Mask = ipv4MaskMax + 1
				Expect(c.IPv4Mask).Should(BeNumerically(">", ipv4MaskMax))
			})
			It("should be disabled", func() {
				c.ValidateConfig(logger)
				Expect(c.IPv4Mask).Should(BeNumerically("==", 0))
			})
		})
		When("IPv6Mask is invalid", func() {
			BeforeEach(func() {
				c.IPv6Mask = ipv6MaskMax + 1
				Expect(c.IPv6Mask).Should(BeNumerically(">", ipv6MaskMax))
			})
			It("should be disabled", func() {
				c.ValidateConfig(logger)
				Expect(c.IPv6Mask).Should(BeNumerically("==", 0))
			})
		})
	})
})
