package schema_test

import (
	"encoding/json"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/0xERR0R/blocky/config/schema"
)

var _ = Describe("ValidateYAML", func() {
	It("accepts a minimal valid config", func() {
		errs, err := schema.ValidateYAML([]byte("upstreams:\n  groups:\n    default:\n      - 1.1.1.1\n"))
		Expect(err).Should(Succeed())
		Expect(errs).Should(BeEmpty())
	})

	It("reports an unknown top-level key with its path", func() {
		errs, err := schema.ValidateYAML([]byte("notARealKey: true\n"))
		Expect(err).Should(Succeed())
		Expect(errs).ShouldNot(BeEmpty())
		Expect(errs[0].String()).Should(ContainSubstring("notARealKey"))
	})

	It("reports a bad enum value", func() {
		errs, err := schema.ValidateYAML([]byte("connectIPVersion: ipv9\n"))
		Expect(err).Should(Succeed())
		Expect(errs).ShouldNot(BeEmpty())
		Expect(errs[0].Path).Should(ContainSubstring("connectIPVersion"))
	})

	It("returns an error for unparseable YAML", func() {
		_, err := schema.ValidateYAML([]byte("\tnot: [valid"))
		Expect(err).Should(HaveOccurred())
	})

	It("accepts valid DNS query types in filtering.queryTypes", func() {
		errs, err := schema.ValidateYAML([]byte("filtering:\n  queryTypes:\n    - A\n    - AAAA\n"))
		Expect(err).Should(Succeed())
		Expect(errs).Should(BeEmpty())
	})

	It("rejects an unknown DNS query type in filtering.queryTypes", func() {
		errs, err := schema.ValidateYAML([]byte("filtering:\n  queryTypes:\n    - NOTAREALTYPE\n"))
		Expect(err).Should(Succeed())
		Expect(errs).ShouldNot(BeEmpty())
		Expect(errs[0].Path).Should(ContainSubstring("queryTypes"))
	})

	// Permissive-superset guards: blocky's TextUnmarshaler-backed scalar types
	// accept both a bare number and its quoted-string form; the schema must
	// accept everything blocky accepts, otherwise a valid config is flagged.
	It("accepts both the integer and quoted-string forms of ECS masks", func() {
		for _, form := range []string{"24", `"24"`} {
			errs, err := schema.ValidateYAML([]byte("ecs:\n  ipv4Mask: " + form + "\n  ipv6Mask: " + form + "\n"))
			Expect(err).Should(Succeed())
			Expect(errs).Should(BeEmpty(),
				"blocky accepts ECS mask form %s via UnmarshalText; the schema must too", form)
		}
	})

	It("accepts both the duration string and the deprecated bare-number (minutes) form", func() {
		for _, form := range []string{"1h", "30"} {
			errs, err := schema.ValidateYAML([]byte("customDNS:\n  customTTL: " + form + "\n"))
			Expect(err).Should(Succeed())
			Expect(errs).Should(BeEmpty(),
				"blocky accepts duration form %s (bare number = deprecated minutes); the schema must too", form)
		}
	})
})

var _ = Describe("schema corpus", func() {
	It("accepts the documented example config docs/config.yml", func() {
		data, err := os.ReadFile("../../docs/config.yml")
		Expect(err).Should(Succeed())

		errs, err := schema.ValidateYAML(data)
		Expect(err).Should(Succeed())
		Expect(errs).Should(BeEmpty(),
			"docs/config.yml must validate against its own schema; "+
				"a finding here means the schema is stricter than blocky (a false-positive)")
	})

	It("accepts a deprecated top-level key (no false-positive mid-migration)", func() {
		// `disableIPv6` is a deprecated *bool alias; blocky still accepts it.
		errs, err := schema.ValidateYAML([]byte("disableIPv6: true\n"))
		Expect(err).Should(Succeed())
		Expect(errs).Should(BeEmpty(),
			"deprecated keys must be in the schema (flattenDeprecated); "+
				"otherwise users mid-migration get a false-positive")
	})

	It("marks deprecated keys as deprecated in the schema document", func() {
		Expect(string(schema.JSON)).Should(ContainSubstring("\"deprecated\": true"))
	})

	Describe("deprecated markers for inline Deprecated blocks", func() {
		var doc map[string]interface{}

		BeforeEach(func() {
			Expect(json.Unmarshal(schema.JSON, &doc)).Should(Succeed())
		})

		// prop navigates nested "properties.<key>" objects to a leaf schema node.
		prop := func(path []string) map[string]interface{} {
			node := doc
			for _, key := range path {
				props, ok := node["properties"].(map[string]interface{})
				Expect(ok).Should(BeTrue(), "expected a properties object on the way to %v", path)
				node, ok = props[key].(map[string]interface{})
				Expect(ok).Should(BeTrue(), "expected property %q on the way to %v", key, path)
			}

			return node
		}

		DescribeTable("marks the key deprecated:true",
			func(path []string) {
				Expect(prop(path)).Should(HaveKeyWithValue("deprecated", true))
			},
			Entry("top-level disableIPv6", []string{"disableIPv6"}),
			Entry("nested blocking.blackLists", []string{"blocking", "blackLists"}),
			Entry("nested blocking.refreshPeriod", []string{"blocking", "refreshPeriod"}),
			Entry("nested hostsFile.filePath", []string{"hostsFile", "filePath"}),
		)
	})
})

var _ = Describe("schema enum value descriptions", func() {
	var doc map[string]interface{}

	BeforeEach(func() {
		Expect(json.Unmarshal(schema.JSON, &doc)).Should(Succeed())
	})

	// description navigates nested "properties.<key>" objects and returns the
	// leaf property's description string.
	description := func(path ...string) string {
		node := doc
		for _, key := range path {
			props, ok := node["properties"].(map[string]interface{})
			Expect(ok).Should(BeTrue(), "expected a properties object on the way to %v", path)
			node, ok = props[key].(map[string]interface{})
			Expect(ok).Should(BeTrue(), "expected property %q on the way to %v", key, path)
		}

		desc, _ := node["description"].(string)

		return desc
	}

	It("documents each upstreams.init.strategy enum value", func() {
		d := description("upstreams", "init", "strategy")
		Expect(d).Should(ContainSubstring("blocking"))
		Expect(d).Should(ContainSubstring("failOnError"))
		Expect(d).Should(ContainSubstring("fast"))
		Expect(d).Should(ContainSubstring("background"), "fast should mention background initialization")
	})

	It("documents each upstreams.strategy enum value", func() {
		d := description("upstreams", "strategy")
		Expect(d).Should(ContainSubstring("parallel_best"))
		Expect(d).Should(ContainSubstring("strict"))
		Expect(d).Should(ContainSubstring("random"))
	})
})

var _ = Describe("schema default value types", func() {
	var doc map[string]interface{}

	BeforeEach(func() {
		Expect(json.Unmarshal(schema.JSON, &doc)).Should(Succeed())
	})

	// defaultAt navigates nested "properties.<key>" objects and returns the
	// leaf property's default.
	defaultAt := func(path ...string) interface{} {
		node := doc
		for _, key := range path {
			props, ok := node["properties"].(map[string]interface{})
			Expect(ok).Should(BeTrue(), "expected a properties object on the way to %v", path)
			node, ok = props[key].(map[string]interface{})
			Expect(ok).Should(BeTrue(), "expected property %q on the way to %v", key, path)
		}

		return node["default"]
	}

	It("emits boolean and integer/number defaults as native JSON types", func() {
		var checked int

		var walk func(node map[string]interface{})
		walk = func(node map[string]interface{}) {
			props, _ := node["properties"].(map[string]interface{})
			for _, raw := range props {
				v, ok := raw.(map[string]interface{})
				if !ok {
					continue
				}

				if def, has := v["default"]; has {
					switch v["type"] {
					case "boolean":
						Expect(def).Should(BeAssignableToTypeOf(false),
							"boolean default must be a JSON bool, got %T (%v)", def, def)
						checked++
					case "integer", "number":
						Expect(def).Should(BeAssignableToTypeOf(float64(0)),
							"%v default must be a JSON number, got %T (%v)", v["type"], def, def)
						checked++
					}
				}

				walk(v)
			}
		}
		walk(doc)

		Expect(checked).Should(BeNumerically(">", 10), "expected to check many typed defaults")
	})

	It("keeps enum and custom string-scalar defaults as strings", func() {
		// enum (string), and Duration (anyOf string/integer) must NOT be coerced.
		Expect(defaultAt("upstreams", "init", "strategy")).Should(Equal("blocking"))
		Expect(defaultAt("customDNS", "customTTL")).Should(Equal("1h"))
	})
})

var _ = Describe("schema field descriptions from Go comments", func() {
	var doc map[string]interface{}

	BeforeEach(func() {
		Expect(json.Unmarshal(schema.JSON, &doc)).Should(Succeed())
	})

	description := func(path ...string) string {
		node := doc
		for _, key := range path {
			props, ok := node["properties"].(map[string]interface{})
			Expect(ok).Should(BeTrue(), "expected a properties object on the way to %v", path)
			node, ok = props[key].(map[string]interface{})
			Expect(ok).Should(BeTrue(), "expected property %q on the way to %v", key, path)
		}

		desc, _ := node["description"].(string)

		return desc
	}

	It("uses a field comment as the description", func() {
		Expect(description("upstreams", "timeout")).Should(ContainSubstring("Timeout for upstream DNS connections"))
	})
})
