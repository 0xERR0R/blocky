package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"
)

// yamlMap builds a generic YAML map from a literal, keeping specs readable.
func yamlMap(doc string) map[interface{}]interface{} {
	var m map[interface{}]interface{}

	Expect(yaml.Unmarshal([]byte(doc), &m)).Should(Succeed())

	return m
}

var _ = Describe("Config file merging", func() {
	Describe("mergeMaps", func() {
		It("unions disjoint keys", func() {
			merged := mergeMaps(yamlMap("a: 1"), yamlMap("b: 2"))

			Expect(merged).Should(Equal(yamlMap("{a: 1, b: 2}")))
		})

		It("merges nested mappings recursively", func() {
			dst := yamlMap("upstreams: {groups: {default: [8.8.8.8]}}")
			src := yamlMap("upstreams: {groups: {special: [1.1.1.1]}}")

			Expect(mergeMaps(dst, src)).Should(Equal(
				yamlMap("upstreams: {groups: {default: [8.8.8.8], special: [1.1.1.1]}}")))
		})

		It("replaces lists wholesale instead of concatenating", func() {
			dst := yamlMap("ports: {dns: [53, 5353]}")
			src := yamlMap("ports: {dns: [1053]}")

			Expect(mergeMaps(dst, src)).Should(Equal(yamlMap("ports: {dns: [1053]}")))
		})

		It("replaces scalars, last wins", func() {
			Expect(mergeMaps(yamlMap("log: {level: info}"), yamlMap("log: {level: debug}"))).
				Should(Equal(yamlMap("log: {level: debug}")))
		})

		It("lets an explicit null win", func() {
			Expect(mergeMaps(yamlMap("blocking: {blockType: zeroIp}"), yamlMap("blocking: null"))).
				Should(Equal(yamlMap("blocking: null")))
		})

		It("replaces on type mismatch (map then scalar, scalar then map)", func() {
			Expect(mergeMaps(yamlMap("a: {b: 1}"), yamlMap("a: 5"))).
				Should(Equal(yamlMap("a: 5")))
			Expect(mergeMaps(yamlMap("a: 5"), yamlMap("a: {b: 1}"))).
				Should(Equal(yamlMap("a: {b: 1}")))
		})

		It("accepts a nil destination", func() {
			Expect(mergeMaps(nil, yamlMap("a: 1"))).Should(Equal(yamlMap("a: 1")))
		})
	})
})
