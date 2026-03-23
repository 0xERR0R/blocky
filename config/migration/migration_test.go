package migration

import (
	"testing"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func TestMigration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Migration Suite")
}

type testDeprecated struct {
	OldName   *string `yaml:"oldName"`
	OldNumber *int    `yaml:"oldNumber"`
	OldUnused *bool   `yaml:"oldUnused"`
}

type testNew struct {
	NewName   string `yaml:"newName"`
	NewNumber int    `yaml:"newNumber"`
	NewUnused bool   `yaml:"newUnused"`
}

var _ = Describe("Migration", func() {
	var (
		logger *logrus.Entry
		hook   *log.MockLoggerHook
	)

	BeforeEach(func() {
		logger, hook = log.NewMockEntry()
	})

	Describe("Migrate", func() {
		It("should not report deprecated usage when no deprecated options are set", func() {
			deprecated := testDeprecated{}
			newCfg := testNew{}

			result := Migrate(logger, "", deprecated, map[string]Migrator{
				"oldName":   Move(To("newName", &newCfg)),
				"oldNumber": Move(To("newNumber", &newCfg)),
				"oldUnused": Move(To("newUnused", &newCfg)),
			})

			Expect(result).Should(BeFalse())
		})

		It("should migrate deprecated option to new location", func() {
			oldVal := "migrated-value"
			deprecated := testDeprecated{OldName: &oldVal}
			newCfg := testNew{}

			result := Migrate(logger, "", deprecated, map[string]Migrator{
				"oldName":   Move(To("newName", &newCfg)),
				"oldNumber": Move(To("newNumber", &newCfg)),
				"oldUnused": Move(To("newUnused", &newCfg)),
			})

			Expect(result).Should(BeTrue())
			Expect(newCfg.NewName).Should(Equal("migrated-value"))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("deprecated")))
		})

		It("should not override new option if already set", func() {
			oldVal := "old-value"
			deprecated := testDeprecated{OldName: &oldVal}
			newCfg := testNew{NewName: "already-set"}

			result := Migrate(logger, "", deprecated, map[string]Migrator{
				"oldName":   Move(To("newName", &newCfg)),
				"oldNumber": Move(To("newNumber", &newCfg)),
				"oldUnused": Move(To("newUnused", &newCfg)),
			})

			Expect(result).Should(BeTrue())
			Expect(newCfg.NewName).Should(Equal("already-set"))
		})

		It("should work with prefix", func() {
			oldVal := "val"
			deprecated := testDeprecated{OldName: &oldVal}
			newCfg := testNew{}

			result := Migrate(logger, "section", deprecated, map[string]Migrator{
				"oldName":   Move(To("newName", &newCfg)),
				"oldNumber": Move(To("newNumber", &newCfg)),
				"oldUnused": Move(To("newUnused", &newCfg)),
			})

			Expect(result).Should(BeTrue())
			Expect(newCfg.NewName).Should(Equal("val"))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("section.oldName")))
		})
	})

	Describe("Apply", func() {
		It("should call apply function with typed value", func() {
			oldVal := 42
			deprecated := testDeprecated{OldNumber: &oldVal}
			newCfg := testNew{}
			applied := false

			result := Migrate(logger, "", deprecated, map[string]Migrator{
				"oldName": Move(To("newName", &newCfg)),
				"oldNumber": Apply(To("newNumber", &newCfg), func(v int) {
					applied = true
					newCfg.NewNumber = v * 2
				}),
				"oldUnused": Move(To("newUnused", &newCfg)),
			})

			Expect(result).Should(BeTrue())
			Expect(applied).Should(BeTrue())
			Expect(newCfg.NewNumber).Should(Equal(84))
		})
	})

	Describe("Dest", func() {
		It("Name should return full name with prefix", func() {
			newCfg := testNew{}
			dest := To("newName", &newCfg)
			dest.prefix = "section"

			Expect(dest.Name()).Should(Equal("section.newName"))
		})

		It("Name should return name without prefix", func() {
			newCfg := testNew{}
			dest := To("newName", &newCfg)

			Expect(dest.Name()).Should(Equal("newName"))
		})

		It("String should return the same as Name", func() {
			newCfg := testNew{}
			dest := To("newName", &newCfg)

			Expect(dest.String()).Should(Equal(dest.Name()))
		})

		It("IsDefault should return true for default value", func() {
			newCfg := testNew{}
			dest := To("newName", &newCfg)

			Expect(dest.IsDefault()).Should(BeTrue())
		})

		It("IsDefault should return false for non-default value", func() {
			newCfg := testNew{NewName: "custom"}
			dest := To("newName", &newCfg)

			Expect(dest.IsDefault()).Should(BeFalse())
		})
	})

	Describe("fullname", func() {
		It("should return name when prefix is empty", func() {
			Expect(fullname("", "name")).Should(Equal("name"))
		})

		It("should return prefix.name when prefix is set", func() {
			Expect(fullname("prefix", "name")).Should(Equal("prefix.name"))
		})
	})
})
