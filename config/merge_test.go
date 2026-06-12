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

	Describe("decodeYAMLDocuments", func() {
		It("decodes a single document", func() {
			docs, err := decodeYAMLDocuments([]byte("log:\n  level: debug\n"))

			Expect(err).Should(Succeed())
			Expect(docs).Should(HaveLen(1))
			Expect(docs[0]).Should(Equal(yamlMap("log: {level: debug}")))
		})

		It("decodes multiple documents separated by ---", func() {
			docs, err := decodeYAMLDocuments([]byte("a: 1\n---\nb: 2\n"))

			Expect(err).Should(Succeed())
			Expect(docs).Should(HaveLen(2))
		})

		It("returns no documents for empty data", func() {
			docs, err := decodeYAMLDocuments([]byte(""))

			Expect(err).Should(Succeed())
			Expect(docs).Should(BeEmpty())
		})

		It("returns no documents for comment-only data", func() {
			docs, err := decodeYAMLDocuments([]byte("# nothing to see here\n"))

			Expect(err).Should(Succeed())
			Expect(docs).Should(BeEmpty())
		})

		It("rejects duplicate keys within one document", func() {
			_, err := decodeYAMLDocuments([]byte("a: 1\na: 2\n"))

			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("already set in map"))
		})

		It("rejects duplicate keys at nested levels too", func() {
			_, err := decodeYAMLDocuments([]byte("a:\n  b: 1\n  b: 2\n"))

			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("already set in map"))
		})

		It("rejects a non-mapping top level", func() {
			_, err := decodeYAMLDocuments([]byte("- just\n- a list\n"))

			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("must be a mapping"))
		})

		It("rejects an alias to an anchor from another file", func() {
			// anchors only live within one document/file now — pin the error
			_, err := decodeYAMLDocuments([]byte("a: *missing\n"))

			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("unknown anchor"))
		})
	})

	Describe("mergeConfigFiles", func() {
		roundtrip := func(data []byte) map[interface{}]interface{} {
			var m map[interface{}]interface{}

			Expect(yaml.Unmarshal(data, &m)).Should(Succeed())

			return m
		}

		It("merges the issue #1827 example: disjoint upstream groups", func() {
			merged, err := mergeConfigFiles([]configFile{
				{path: "00_default.yaml", data: []byte("upstreams:\n  groups:\n    default: [8.8.8.8]\n  strategy: parallel_best\n")},
				{path: "10_local.yaml", data: []byte("upstreams:\n  groups:\n    192.168.0.0/16: [1.1.1.1]\n")},
			})

			Expect(err).Should(Succeed())
			Expect(roundtrip(merged)).Should(Equal(yamlMap(
				"upstreams: {groups: {default: [8.8.8.8], 192.168.0.0/16: [1.1.1.1]}, strategy: parallel_best}")))
		})

		It("applies files in the given order: later file wins", func() {
			merged, err := mergeConfigFiles([]configFile{
				{path: "a.yaml", data: []byte("log: {level: info}")},
				{path: "b.yaml", data: []byte("log: {level: debug}")},
			})

			Expect(err).Should(Succeed())
			Expect(roundtrip(merged)).Should(Equal(yamlMap("log: {level: debug}")))
		})

		It("merges documents within one file in order, like separate files", func() {
			merged, err := mergeConfigFiles([]configFile{
				{path: "multi.yaml", data: []byte("log: {level: info}\n---\nlog: {level: debug}\n")},
			})

			Expect(err).Should(Succeed())
			Expect(roundtrip(merged)).Should(Equal(yamlMap("log: {level: debug}")))
		})

		It("returns nil when no file contains a document", func() {
			merged, err := mergeConfigFiles([]configFile{
				{path: "empty.yaml", data: []byte("")},
			})

			Expect(err).Should(Succeed())
			Expect(merged).Should(BeNil())
		})

		It("names the offending file on parse errors", func() {
			_, err := mergeConfigFiles([]configFile{
				{path: "good.yaml", data: []byte("a: 1")},
				{path: "bad.yaml", data: []byte("a: 1\na: 2\n")},
			})

			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("bad.yaml"))
		})
	})
})
