package config

import (
	"time"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CachingConfig", func() {
	var cfg CachingConfig

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = CachingConfig{
			MaxCachingTime: Duration(time.Hour),
		}
	})

	Describe("IsEnabled", func() {
		It("should be true by default", func() {
			cfg := CachingConfig{}
			Expect(defaults.Set(&cfg)).Should(Succeed())

			Expect(cfg.IsEnabled()).Should(BeTrue())
		})

		When("the config is disabled", func() {
			BeforeEach(func() {
				cfg = CachingConfig{
					MaxCachingTime: Duration(time.Hour * -1),
				}
			})
			It("should be false", func() {
				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})

		When("the config is enabled", func() {
			It("should be true", func() {
				Expect(cfg.IsEnabled()).Should(BeTrue())
			})
		})

		When("the config is disabled", func() {
			It("should be false", func() {
				cfg := CachingConfig{
					MaxCachingTime: Duration(-1),
				}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		When("prefetching is enabled", func() {
			BeforeEach(func() {
				cfg = CachingConfig{
					Prefetching: true,
				}
			})

			It("should return configuration", func() {
				cfg.LogConfig(logger)

				Expect(hook.Calls).ShouldNot(BeEmpty())
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("prefetching:")))
			})
		})
	})

	Describe("EnablePrefetch", func() {
		When("prefetching is enabled", func() {
			BeforeEach(func() {
				cfg = CachingConfig{}
			})

			It("should return configuration", func() {
				cfg.EnablePrefetch()

				Expect(cfg.Prefetching).Should(BeTrue())
				Expect(cfg.PrefetchThreshold).Should(Equal(0))
				Expect(cfg.MaxCachingTime).Should(BeZero())
			})
		})
	})
})
