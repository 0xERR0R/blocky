package config

import (
	"github.com/0xERR0R/blocky/log"
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Redis", func() {
	var (
		c   Redis
		err error
	)

	suiteBeforeEach()

	BeforeEach(func() {
		err = defaults.Set(&c)
		Expect(err).Should(Succeed())
	})

	Describe("IsEnabled", func() {
		When("all fields are default", func() {
			It("should be disabled", func() {
				Expect(c.IsEnabled()).Should(BeFalse())
			})
		})

		When("Address is set", func() {
			BeforeEach(func() {
				c.Address = "localhost:6379"
			})

			It("should be enabled", func() {
				Expect(c.IsEnabled()).Should(BeTrue())
			})
		})
	})

	Describe("LogConfig", func() {
		BeforeEach(func() {
			logger, hook = log.NewMockEntry()
		})

		When("all fields are default", func() {
			It("should log default values", func() {
				c.LogConfig(logger)

				Expect(hook.Messages).Should(
					SatisfyAll(ContainElement(ContainSubstring("address: ")),
						ContainElement(ContainSubstring("username: ")),
						ContainElement(ContainSubstring("password: ")),
						ContainElement(ContainSubstring("database: ")),
						ContainElement(ContainSubstring("required: ")),
						ContainElement(ContainSubstring("connectionAttempts: ")),
						ContainElement(ContainSubstring("connectionCooldown: "))))
			})
		})

		When("Address is set", func() {
			BeforeEach(func() {
				c.Address = "localhost:6379"
			})

			It("should log address", func() {
				c.LogConfig(logger)

				Expect(hook.Messages).Should(ContainElement(ContainSubstring("address: localhost:6379")))
			})
		})

		When("SentinelAddresses is set", func() {
			BeforeEach(func() {
				c.SentinelAddresses = []string{"localhost:26379", "localhost:26380"}
			})

			It("should log sentinel addresses", func() {
				c.LogConfig(logger)

				Expect(hook.Messages).Should(
					SatisfyAll(
						ContainElement(ContainSubstring("sentinel:")),
						ContainElement(ContainSubstring("  addresses:")),
						ContainElement(ContainSubstring("  - localhost:26379")),
						ContainElement(ContainSubstring("  - localhost:26380"))))
			})
		})
	})

	Describe("obfuscatePassword", func() {
		When("password is empty", func() {
			It("should return empty string", func() {
				Expect(obfuscatePassword("")).Should(Equal(""))
			})
		})

		When("password is not empty", func() {
			It("should return obfuscated password", func() {
				Expect(obfuscatePassword("test123")).Should(Equal("*******"))
			})
		})
	})
})
