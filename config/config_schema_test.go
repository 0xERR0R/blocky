package config

import (
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
})
