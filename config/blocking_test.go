package config

import (
	"time"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("BlockingConfig", func() {
	var (
		cfg BlockingConfig
	)

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = BlockingConfig{
			BlockType: "ZEROIP",
			BlockTTL:  Duration(time.Minute),
			BlackLists: map[string][]string{
				"gr1": {"/a/file/path"},
			},
			ClientGroupsBlock: map[string][]string{
				"default": {"gr1"},
			},
			RefreshPeriod: Duration(time.Hour),
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := BlockingConfig{}
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
				cfg := BlockingConfig{
					BlockTTL: Duration(-1),
				}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages[0]).Should(Equal("clientGroupsBlock:"))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("refresh = every 1 hour")))
		})
		When("refresh is disabled", func() {
			It("should reflect that", func() {
				cfg.RefreshPeriod = Duration(-1)

				logger.Logger.Level = logrus.InfoLevel

				cfg.LogConfig(logger)

				Expect(hook.Calls).ShouldNot(BeEmpty())
				Expect(hook.Messages).ShouldNot(ContainElement(ContainSubstring("refresh = disabled")))

				logger.Logger.Level = logrus.TraceLevel

				cfg.LogConfig(logger)

				Expect(hook.Calls).ShouldNot(BeEmpty())
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("refresh = disabled")))
			})
		})
	})
})
