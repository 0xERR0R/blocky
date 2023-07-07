package config

import (
	"time"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HostsFileConfig", func() {
	var cfg HostsFileConfig

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = HostsFileConfig{
			Sources: append(
				NewBytesSources("/a/file/path"),
				TextBytesSource("127.0.0.1 localhost"),
			),
			HostsTTL:       Duration(29 * time.Minute),
			Loading:        SourceLoadingConfig{RefreshPeriod: Duration(30 * time.Minute)},
			FilterLoopback: true,
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := HostsFileConfig{}
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
				cfg := HostsFileConfig{}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("- file:///a/file/path")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("- 127.0.0.1 lo...")))
		})
	})

	Describe("migrate", func() {
		It("should", func() {
			cfg, err := WithDefaults[HostsFileConfig]()
			Expect(err).Should(Succeed())

			cfg.Deprecated.Filepath = ptrOf(newBytesSource("/a/file/path"))
			cfg.Deprecated.RefreshPeriod = ptrOf(Duration(time.Hour))

			migrated := cfg.migrate(logger)
			Expect(migrated).Should(BeTrue())

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("hostsFile.loading.refreshPeriod")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("hostsFile.sources")))

			Expect(cfg.Sources).Should(Equal([]BytesSource{*cfg.Deprecated.Filepath}))
			Expect(cfg.Loading.RefreshPeriod).Should(Equal(*cfg.Deprecated.RefreshPeriod))
		})
	})
})
