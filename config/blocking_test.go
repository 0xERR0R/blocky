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

		It("should log time-range schedules", func() {
			cfg.Schedules = map[string]Schedule{
				"night": {Start: "22:00", End: "07:00", Weekdays: []Weekday{Weekday(time.Monday)}},
			}
			cfg.LogConfig(logger)

			Expect(hook.Messages).Should(ContainElement(Equal("schedules:")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("night: 22:00 - 07:00")))
		})

		It("should log full-day schedules", func() {
			cfg.Schedules = map[string]Schedule{
				"weekend": {Weekdays: []Weekday{Weekday(time.Saturday), Weekday(time.Sunday)}},
			}
			cfg.LogConfig(logger)

			Expect(hook.Messages).Should(ContainElement(Equal("schedules:")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("weekend: all day")))
		})

		It("should log listSchedules", func() {
			cfg.ListSchedules = map[string][]string{
				"gr1": {"night"},
			}
			cfg.LogConfig(logger)

			Expect(hook.Messages).Should(ContainElement(Equal("listSchedules:")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("gr1 = [night]")))
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

	Describe("validate", func() {
		When("blocking is disabled", func() {
			It("should not return error", func() {
				cfg := Blocking{}
				Expect(cfg.validate()).Should(Succeed())
			})
		})

		When("only references existing lists", func() {
			It("should not return error", func() {
				Expect(cfg.validate()).Should(Succeed())
			})
		})

		When("references non-existing lists", func() {
			It("should return error", func() {
				cfg := Blocking{
					ClientGroupsBlock: map[string][]string{
						"default": {"non-existing-group"},
					},
				}
				err := cfg.validate()
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("references undefined allowlist or denylist"))
			})
		})
	})
})
