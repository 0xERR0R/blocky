package config

import (
	"github.com/0xERR0R/blocky/log"
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"
)

var _ = Describe("ECS", func() {
	var (
		c   ECS
		err error
	)

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

		When("UseAsClient is true", func() {
			BeforeEach(func() {
				c.UseAsClient = true
			})

			It("should be enabled", func() {
				Expect(c.IsEnabled()).Should(BeTrue())
			})
		})

		When("Forward is true", func() {
			BeforeEach(func() {
				c.Forward = true
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

	Describe("LogConfig", func() {
		BeforeEach(func() {
			logger, hook = log.NewMockEntry()
		})

		It("should log configuration", func() {
			c.LogConfig(logger)

			Expect(hook.Calls).Should(HaveLen(4))
			Expect(hook.Messages).Should(ContainElements(
				ContainSubstring("Use as client"),
				ContainSubstring("Forward"),
				ContainSubstring("IPv4 netmask"),
				ContainSubstring("IPv6 netmask"),
			))
		})
	})

	Describe("Parse", func() {
		var data []byte

		Context("IPv4Mask", func() {
			var ipmask ECSv4Mask

			When("Parse correct value", func() {
				BeforeEach(func() {
					data = []byte("24")
					err = yaml.Unmarshal(data, &ipmask)
					Expect(err).Should(Succeed())
				})

				It("should be value", func() {
					Expect(ipmask).Should(Equal(ECSv4Mask(24)))
				})
			})

			When("Parse NaN value", func() {
				BeforeEach(func() {
					data = []byte("FALSE")
					err = yaml.Unmarshal(data, &ipmask)
				})

				It("should be error", func() {
					Expect(err).Should(HaveOccurred())
				})
			})

			When("Parse incorrect value", func() {
				BeforeEach(func() {
					data = []byte("35")
					err = yaml.Unmarshal(data, &ipmask)
				})

				It("should be error", func() {
					Expect(err).Should(HaveOccurred())
				})
			})
		})

		Context("IPv6Mask", func() {
			var ipmask ECSv6Mask

			When("Parse correct value", func() {
				BeforeEach(func() {
					data = []byte("64")
					err = yaml.Unmarshal(data, &ipmask)
					Expect(err).Should(Succeed())
				})

				It("should be value", func() {
					Expect(ipmask).Should(Equal(ECSv6Mask(64)))
				})
			})

			When("Parse NaN value", func() {
				BeforeEach(func() {
					data = []byte("FALSE")
					err = yaml.Unmarshal(data, &ipmask)
				})

				It("should be error", func() {
					Expect(err).Should(HaveOccurred())
				})
			})

			When("Parse incorrect value", func() {
				BeforeEach(func() {
					data = []byte("130")
					err = yaml.Unmarshal(data, &ipmask)
				})

				It("should be error", func() {
					Expect(err).Should(HaveOccurred())
				})
			})
		})
	})
})
