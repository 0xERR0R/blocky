package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	yamlv2 "gopkg.in/yaml.v2"
	yaml "gopkg.in/yaml.v3"
)

// yamlMap builds a generic YAML map from a literal, keeping specs readable.
func yamlMap(doc string) map[any]any {
	var m map[any]any

	Expect(yamlv2.Unmarshal([]byte(doc), &m)).Should(Succeed())

	return m
}

// nodeToMap re-encodes a merged yaml.v3 node and decodes it with yaml.v2, the
// way the real config pipeline does, so node specs can compare semantics.
func nodeToMap(node *yaml.Node) map[any]any {
	out, err := yaml.Marshal(node)
	Expect(err).Should(Succeed())

	var m map[any]any

	Expect(yamlv2.Unmarshal(out, &m)).Should(Succeed())

	return m
}

var _ = Describe("Config file merging", func() {
	// roundtrip decodes merged bytes with yaml.v2 (the real config decoder) so
	// merge specs compare semantics rather than byte layout.
	roundtrip := func(data []byte) map[any]any {
		var m map[any]any

		Expect(yamlv2.Unmarshal(data, &m)).Should(Succeed())

		return m
	}

	// merge2 merges two single-document files in order and returns the decoded
	// result. It re-homes the old mergeMaps unit specs at the public boundary.
	merge2 := func(first, second string) map[any]any {
		merged, err := mergeConfigFiles([]configFile{
			{path: "00_first.yaml", data: []byte(first)},
			{path: "10_second.yaml", data: []byte(second)},
		})

		Expect(err).Should(Succeed())

		return roundtrip(merged)
	}

	Describe("merge semantics", func() {
		It("unions disjoint keys", func() {
			Expect(merge2("a: 1", "b: 2")).Should(Equal(yamlMap("{a: 1, b: 2}")))
		})

		It("merges nested mappings recursively", func() {
			Expect(merge2(
				"upstreams: {groups: {default: [8.8.8.8]}}",
				"upstreams: {groups: {special: [1.1.1.1]}}",
			)).Should(Equal(yamlMap("upstreams: {groups: {default: [8.8.8.8], special: [1.1.1.1]}}")))
		})

		It("replaces lists wholesale instead of concatenating", func() {
			Expect(merge2("ports: {dns: [53, 5353]}", "ports: {dns: [1053]}")).
				Should(Equal(yamlMap("ports: {dns: [1053]}")))
		})

		It("replaces scalars, last wins", func() {
			Expect(merge2("log: {level: info}", "log: {level: debug}")).
				Should(Equal(yamlMap("log: {level: debug}")))
		})

		It("lets an explicit null win", func() {
			Expect(merge2("blocking: {blockType: zeroIp}", "blocking: null")).
				Should(Equal(yamlMap("blocking: null")))
		})

		It("replaces on type mismatch (map then scalar)", func() {
			Expect(merge2("a: {b: 1}", "a: 5")).Should(Equal(yamlMap("a: 5")))
		})

		It("replaces on type mismatch (scalar then map)", func() {
			Expect(merge2("a: 5", "a: {b: 1}")).Should(Equal(yamlMap("a: {b: 1}")))
		})

		It("keeps first-seen key order, appending new keys at the end", func() {
			merged, err := mergeConfigFiles([]configFile{
				{path: "00_first.yaml", data: []byte("a: 1\nb: 2\n")},
				{path: "10_second.yaml", data: []byte("c: 3\na: 9\n")},
			})

			Expect(err).Should(Succeed())
			Expect(string(merged)).Should(Equal("a: 9\nb: 2\nc: 3\n"))
		})
	})

	Describe("decodeYAMLDocuments", func() {
		It("decodes a single document", func() {
			docs, err := decodeYAMLDocuments([]byte("log:\n  level: debug\n"))

			Expect(err).Should(Succeed())
			Expect(docs).Should(HaveLen(1))
			Expect(docs[0].Kind).Should(Equal(yaml.MappingNode))
			Expect(nodeToMap(docs[0])).Should(Equal(yamlMap("log: {level: debug}")))
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

		It("skips a bare null document", func() {
			docs, err := decodeYAMLDocuments([]byte("---\nnull\n"))

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

		It("rejects a self-referential anchor cycle instead of hanging", func() {
			_, err := decodeYAMLDocuments([]byte("a: &x [*x]\n"))

			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("cycle"))
		})
	})

	Describe("mergeConfigFiles", func() {
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

		It("expands a within-file anchor before merging", func() {
			merged, err := mergeConfigFiles([]configFile{
				{path: "a.yaml", data: []byte("base: &b\n  a: 1\nderived: *b\n")},
			})

			Expect(err).Should(Succeed())

			m := roundtrip(merged)
			derived, ok := m["derived"].(map[any]any)
			Expect(ok).Should(BeTrue())
			Expect(derived["a"]).Should(Equal(1))
			// No anchor name survives into the merged document.
			Expect(string(merged)).ShouldNot(ContainSubstring("&b"))
			Expect(string(merged)).ShouldNot(ContainSubstring("*b"))
		})

		It("resolves a within-file merge key (<<) end to end under strict decoding", func() {
			merged, err := mergeConfigFiles([]configFile{
				{path: "a.yaml", data: []byte("base: &base\n  a: 1\n  b: 2\nderived:\n  <<: *base\n  c: 3\n")},
			})

			Expect(err).Should(Succeed())

			// The real config decoder is yaml.v2 strict; it must resolve the
			// expanded merge key without complaint.
			var strict map[any]any
			Expect(yamlv2.UnmarshalStrict(merged, &strict)).Should(Succeed())

			derived, ok := strict["derived"].(map[any]any)
			Expect(ok).Should(BeTrue())
			Expect(derived["a"]).Should(Equal(1))
			Expect(derived["b"]).Should(Equal(2))
			Expect(derived["c"]).Should(Equal(3))
		})

		Describe("scalar fidelity (issue #1827 pivot)", func() {
			It("keeps an unquoted decimal like 1.0 instead of collapsing to 1", func() {
				merged, err := mergeConfigFiles([]configFile{
					{path: "a.yaml", data: []byte("minTlsServeVersion: 1.0\n")},
				})

				Expect(err).Should(Succeed())
				Expect(string(merged)).Should(ContainSubstring("minTlsServeVersion: 1.0"))
			})

			It("keeps a plain unquoted yes instead of rewriting it to true", func() {
				merged, err := mergeConfigFiles([]configFile{
					{path: "a.yaml", data: []byte("someKey: yes\n")},
				})

				Expect(err).Should(Succeed())
				Expect(string(merged)).Should(ContainSubstring("someKey: yes"))
			})

			It("keeps an octal literal like 0700 instead of decimal 448", func() {
				merged, err := mergeConfigFiles([]configFile{
					{path: "a.yaml", data: []byte("mode: 0700\n")},
				})

				Expect(err).Should(Succeed())
				Expect(string(merged)).Should(ContainSubstring("0700"))
				Expect(string(merged)).ShouldNot(ContainSubstring("448"))
			})

			It("keeps a quoted string like \"1.0\" quoted", func() {
				merged, err := mergeConfigFiles([]configFile{
					{path: "a.yaml", data: []byte("version: \"1.0\"\n")},
				})

				Expect(err).Should(Succeed())
				Expect(string(merged)).Should(ContainSubstring("\"1.0\""))
			})

			It("keeps a sexagesimal-looking value like 1:30 instead of 90", func() {
				merged, err := mergeConfigFiles([]configFile{
					{path: "a.yaml", data: []byte("window: 1:30\n")},
				})

				Expect(err).Should(Succeed())
				Expect(string(merged)).Should(ContainSubstring("1:30"))
				Expect(string(merged)).ShouldNot(ContainSubstring("window: 90"))
			})
		})
	})
})
