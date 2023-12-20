package config

import (
	"time"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HostsFileConfig", func() {
	var cfg HostsFile

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = HostsFile{
			Sources: append(
				NewBytesSources("/a/file/path"),
				TextBytesSource("127.0.0.1 localhost"),
			),
			HostsTTL:       Duration(29 * time.Minute),
			Loading:        SourceLoading{RefreshPeriod: Duration(30 * time.Minute)},
			FilterLoopback: true,
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := HostsFile{}
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
				cfg := HostsFile{}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElements(
				ContainSubstring("- file:///a/file/path"),
				ContainSubstring("- 127.0.0.1 lo..."),
			))
		})
	})

	Describe("migrate", func() {
		It("should", func() {
			cfg, err := WithDefaults[HostsFile]()
			Expect(err).Should(Succeed())

			cfg.Deprecated.Filepath = ptrOf(newBytesSource("/a/file/path"))
			cfg.Deprecated.RefreshPeriod = ptrOf(Duration(time.Hour))

			migrated := cfg.migrate(logger)
			Expect(migrated).Should(BeTrue())

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElements(
				ContainSubstring("hostsFile.loading.refreshPeriod"),
				ContainSubstring("hostsFile.sources"),
			))

			Expect(cfg.Sources).Should(Equal([]BytesSource{*cfg.Deprecated.Filepath}))
			Expect(cfg.Loading.RefreshPeriod).Should(Equal(*cfg.Deprecated.RefreshPeriod))
		})
	})
})
