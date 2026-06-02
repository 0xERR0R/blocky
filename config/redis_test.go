package config

import (
	"os"
	"path/filepath"

	"github.com/0xERR0R/blocky/log"
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"
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

		const secretValue = "secret-value"

		It("should not log the password", func() {
			c.Password = secretValue
			c.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).ShouldNot(ContainElement(ContainSubstring(secretValue)))
		})

		It("should not log the sentinel password", func() {
			c.SentinelPassword = secretValue
			c.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).ShouldNot(ContainElement(ContainSubstring(secretValue)))
		})
	})

	Describe("file: secret resolution", func() {
		It("loads password from a file, stripping the trailing newline", func() {
			dir := GinkgoT().TempDir()
			pwPath := filepath.Join(dir, "pw")
			Expect(os.WriteFile(pwPath, []byte("redispass\n"), 0o600)).Should(Succeed())

			var redisCfg Redis
			Expect(yaml.UnmarshalStrict(
				[]byte("address: localhost:6379\npassword: file:"+pwPath+"\n"), &redisCfg)).Should(Succeed())
			Expect(redisCfg.Password.Reveal()).Should(Equal("redispass"))
		})

		It("loads sentinelPassword from a file", func() {
			dir := GinkgoT().TempDir()
			sentPath := filepath.Join(dir, "sent")
			Expect(os.WriteFile(sentPath, []byte("sentpass"), 0o600)).Should(Succeed())

			var redisCfg Redis
			Expect(yaml.UnmarshalStrict(
				[]byte("address: localhost:6379\nsentinelPassword: file:"+sentPath+"\n"), &redisCfg)).Should(Succeed())
			Expect(redisCfg.SentinelPassword.Reveal()).Should(Equal("sentpass"))
		})

		It("still obfuscates a file-loaded password in LogConfig", func() {
			logger, hook = log.NewMockEntry()

			dir := GinkgoT().TempDir()
			pwPath := filepath.Join(dir, "pw")
			Expect(os.WriteFile(pwPath, []byte("redispass"), 0o600)).Should(Succeed())

			var redisCfg Redis
			Expect(defaults.Set(&redisCfg)).Should(Succeed())
			Expect(yaml.UnmarshalStrict(
				[]byte("address: localhost:6379\npassword: file:"+pwPath+"\n"), &redisCfg)).Should(Succeed())

			redisCfg.LogConfig(logger)

			Expect(hook.Messages).ShouldNot(ContainElement(ContainSubstring("redispass")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring(secretObfuscator)))
		})
	})
})
