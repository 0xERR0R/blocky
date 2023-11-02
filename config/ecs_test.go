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

	Describe("IsEnabled", func() {
		When("all fields are default", func() {
			It("should be disabled", func() {
				Expect(c.IsEnabled()).Should(BeFalse())
			})
		})
		When("UseEcsAsClient is true", func() {
			BeforeEach(func() {
				c.UseEcsAsClient = true
			})
			It("should be enabled", func() {
				Expect(c.IsEnabled()).Should(BeTrue())
			})
		})
		When("ForwardEcs is true", func() {
			BeforeEach(func() {
				c.ForwardEcs = true
			})
			It("should be enabled", func() {
				Expect(c.IsEnabled()).Should(BeTrue())
			})
		})
		When("IPv4Mask is set", func() {
			BeforeEach(func() {
				c.IPv4Mask = 24
			})
			It("should be enabled", func() {
				Expect(c.IsEnabled()).Should(BeTrue())
			})
		})
		When("IPv6Mask is set", func() {
			BeforeEach(func() {
				c.IPv6Mask = 64
			})
			It("should be enabled", func() {
				Expect(c.IsEnabled()).Should(BeTrue())
			})
		})
	})
})
