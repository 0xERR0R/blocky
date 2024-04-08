package config

import (
	"time"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("BlockingConfig", func() {
	var cfg Blocking

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = Blocking{
			BlockType: "ZEROIP",
			BlockTTL:  Duration(time.Minute),
			Denylists: map[string][]BytesSource{
				"gr1": NewBytesSources("/a/file/path"),
			},
			ClientGroupsBlock: map[string][]string{
				"default": {"gr1"},
			},
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := Blocking{}
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
				cfg := Blocking{
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
			Expect(hook.Messages).Should(ContainElement(Equal("blockType = ZEROIP")))
		})
	})

	Describe("migrate", func() {
		It("should copy values", func() {
			cfg, err := WithDefaults[Blocking]()
			Expect(err).Should(Succeed())

			cfg.Deprecated.BlackLists = &map[string][]BytesSource{
				"deny-group": NewBytesSources("/deny.txt"),
			}
			cfg.Deprecated.WhiteLists = &map[string][]BytesSource{
				"allow-group": NewBytesSources("/allow.txt"),
			}

			migrated := cfg.migrate(logger)
			Expect(migrated).Should(BeTrue())

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElements(
				ContainSubstring("blocking.allowlists"),
				ContainSubstring("blocking.denylists"),
			))

			Expect(cfg.Allowlists).Should(Equal(*cfg.Deprecated.WhiteLists))
			Expect(cfg.Denylists).Should(Equal(*cfg.Deprecated.BlackLists))
		})
	})
})
