package config

import (
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	testAddress = "test-address"
	masterSet   = "test-set"
)

var _ = Describe("RedisConfig", func() {
	var err error
	Describe("Deprecated parameters are converted", func() {
		var c Config
		BeforeEach(func() {
			err := defaults.Set(&c)
			Expect(err).Should(Succeed())
		})
		When("parameter 'address' is set", func() {
			c.Redis.Address = testAddress
			err = validateConfig(&c)
			Expect(err).Should(Succeed())
			Expect(c.Redis.Addresses).Should(HaveLen(1))
			Expect(c.Redis.Addresses).Should(ContainElement(testAddress))
		})
		When("parameter 'sentinelAddresses' is setwith master set", func() {
			c.Redis.SentinelAddresses = []string{testAddress}
			c.Redis.SentinelMasterSet = masterSet
			err = validateConfig(&c)
			Expect(err).Should(Succeed())
			Expect(c.Redis.Addresses).Should(HaveLen(1))
			Expect(c.Redis.Addresses).Should(ContainElement(testAddress))
		})
	})
	Describe("Deprecated parameters are not converted", func() {
		var c Config
		BeforeEach(func() {
			err := defaults.Set(&c)
			Expect(err).Should(Succeed())
		})
		When("parameter 'sentinelAddresses' is set without master set", func() {
			c.Redis.SentinelAddresses = []string{testAddress}
			err = validateConfig(&c)
			Expect(err).ShouldNot(Succeed())
		})
	})
})
