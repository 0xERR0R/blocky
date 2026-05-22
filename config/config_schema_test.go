package config

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("schema-enriched config loading", func() {
	suiteBeforeEach()

	When("config has an unknown key", func() {
		It("returns a schema-enriched error naming the offending field", func() {
			err := unmarshalConfig(logger, []byte("notARealKey: true\n"), &Config{})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("notARealKey"))
			// schema phrasing, not yaml's "not found in type ..."
			Expect(err.Error()).Should(ContainSubstring("not allowed"))
		})
	})

	When("config is valid", func() {
		It("loads without error and without schema warnings", func() {
			data := []byte("upstreams:\n  groups:\n    default:\n      - 1.1.1.1\n")

			err := unmarshalConfig(logger, data, &Config{})
			Expect(err).Should(Succeed())
			Expect(hook.Messages).ShouldNot(ContainElement(ContainSubstring("does not match schema")))
		})
	})

	When("a config exercises flexible/edge value forms not covered by docs/config.yml", func() {
		It("is accepted by both the parser and the schema (permissive-superset)", func() {
			// testdata/superset_config.yml uses the alternative forms blocky
			// accepts (bare-number durations, quoted ECS masks, quoted NULL
			// query type, string TLS version, comma-string listen/mappings,
			// deprecated keys). unmarshalConfig both parses (UnmarshalStrict)
			// and warns on any schema divergence, so this asserts the schema is
			// a true superset of what blocky accepts for all of them.
			data, err := os.ReadFile("testdata/superset_config.yml")
			Expect(err).Should(Succeed())

			err = unmarshalConfig(logger, data, &Config{})
			Expect(err).Should(Succeed())
			Expect(hook.Messages).ShouldNot(ContainElement(ContainSubstring("does not match schema")),
				"every form in testdata/superset_config.yml must validate against the schema too")
		})
	})
})
