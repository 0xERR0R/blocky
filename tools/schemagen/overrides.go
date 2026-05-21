package main

import (
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/invopop/jsonschema"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// qtypeNames returns the sorted DNS query-type names blocky accepts. It is the
// exact set QType.UnmarshalText looks up in dns.StringToType, so a schema enum
// built from it can never be a false-positive.
func qtypeNames() []string {
	names := make([]string, 0, len(dns.StringToType))
	for name := range dns.StringToType {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

// --- small schema constructors (always fresh; see makeMapper) ---

func plain(t string) *jsonschema.Schema { return &jsonschema.Schema{Type: t} }

func arrayOf(items *jsonschema.Schema) *jsonschema.Schema {
	return &jsonschema.Schema{Type: "array", Items: items}
}

func anyOf(schemas ...*jsonschema.Schema) *jsonschema.Schema {
	return &jsonschema.Schema{AnyOf: schemas}
}

// openMap is a JSON object with arbitrary keys and the given value schema.
func openMap(values *jsonschema.Schema) *jsonschema.Schema {
	return &jsonschema.Schema{Type: "object", AdditionalProperties: values}
}

// stringSchema builds a {"type":"string"} schema with docs/examples.
func stringSchema(description string, examples ...string) *jsonschema.Schema {
	s := &jsonschema.Schema{Type: "string", Description: description}
	for _, e := range examples {
		s.Examples = append(s.Examples, e)
	}

	return s
}

// enumStringSchema builds a {"type":"string","enum":[...]} schema.
func enumStringSchema(names []string) *jsonschema.Schema {
	s := &jsonschema.Schema{Type: "string"}
	for _, n := range names {
		s.Enum = append(s.Enum, n)
	}

	return s
}

// bootstrappedUpstreamSchema accepts either a plain upstream string or the
// {upstream, ips} object form (see BootstrappedUpstream.UnmarshalYAML).
func bootstrappedUpstreamSchema() *jsonschema.Schema {
	props := jsonschema.NewProperties()
	props.Set("upstream", plain("string"))
	props.Set("ips", arrayOf(plain("string")))

	obj := &jsonschema.Schema{
		Type:                 "object",
		Properties:           props,
		AdditionalProperties: jsonschema.FalseSchema,
	}

	return anyOf(plain("string"), obj)
}

// --- registries ---
//
// MAINTENANCE: these registries are the manual extension point. When you add a
// new config type that does NOT serialize as a plain JSON object, register it
// here, otherwise the generated schema becomes stricter than blocky (a
// false-positive):
//   - go-enum / string-enum type      -> enumNames    (adds the enum dropdown)
//   - custom UnmarshalText-from-string -> stringForms  (plain string)
//   - string-or-array / map / object   -> complexForms (the flexible shapes)
//
// A miss is not fatal: a divergence on an accepted config is logged as a
// warning, never a failed start. The safety net is the corpus test in
// config/schema, which validates docs/config.yml against the schema — so when
// you add a config option, add it to docs/config.yml and the test will catch a
// missing override here.

// stringSpec describes a loose string override (built fresh per use).
type stringSpec struct {
	description string
	examples    []string
}

// enumNames maps go-enum string types to their generated Names() lists. These
// are exact: the same source the Go parser uses, so enum constraints can never
// be a false-positive. (TLSVersion is handled separately: it may also appear as
// an unquoted YAML number.)
func enumNames() map[reflect.Type][]string {
	return map[reflect.Type][]string{
		reflect.TypeOf(config.NetProtocol(0)):      config.NetProtocolNames(),
		reflect.TypeOf(config.IPVersion(0)):        config.IPVersionNames(),
		reflect.TypeOf(config.QueryLogType(0)):     config.QueryLogTypeNames(),
		reflect.TypeOf(config.UpstreamStrategy(0)): config.UpstreamStrategyNames(),
		reflect.TypeOf(config.BytesSourceType(0)):  config.BytesSourceTypeNames(),
		reflect.TypeOf(config.InitStrategy(0)):     config.InitStrategyNames(),
		reflect.TypeOf(config.QueryLogField("")):   config.QueryLogFieldNames(),
		reflect.TypeOf(log.FormatType(0)):          log.FormatTypeNames(),
	}
}

// stringForms maps types that unmarshal from a *string* to a loose string
// schema spec. No narrow regex: the Go parser is their real validator, so a
// pattern risks false-positives (see spec, permissive-superset principle).
func stringForms() map[reflect.Type]stringSpec {
	return map[reflect.Type]stringSpec{
		reflect.TypeOf(config.Upstream{}): {
			"Upstream DNS server: [net]:host[:port][/path][#commonName] or sdns://...",
			[]string{"tcp+udp:1.1.1.1", "https://dns.google/dns-query", "tcp-tls:1.1.1.1:853"},
		},
		reflect.TypeOf(config.BytesSource{}): {
			"Source: an http(s) URL, a local file path, or an inline YAML block.",
			[]string{"https://example.com/list.txt", "/etc/blocky/list.txt"},
		},
		reflect.TypeOf(config.Weekday(0)): {
			"Day of week: mon, tue, wed, thu, fri, sat, sun.", []string{"mon", "sat"},
		},
		reflect.TypeOf(netip.Prefix{}): {
			"CIDR network prefix.", []string{"64:ff9b::/96"},
		},
		reflect.TypeOf(config.ZoneFileDNS{}): {
			"Inline DNS zone file content.", nil,
		},
		reflect.TypeOf(logrus.Level(0)): {
			"Log level: trace, debug, info, warn, error, fatal.", []string{"info", "debug"},
		},
	}
}

// complexForms maps the flexible container types (string-or-object,
// single-or-list, open maps, sets) to permissive schemas mirroring their
// custom UnmarshalYAML. Each entry is a constructor so every use site gets a
// fresh schema (see makeMapper).
func complexForms() map[reflect.Type]func() *jsonschema.Schema {
	return map[reflect.Type]func() *jsonschema.Schema{
		// Ports accept a string, a bare number, or an array of either.
		reflect.TypeOf(config.ListenConfig(nil)): func() *jsonschema.Schema {
			return anyOf(plain("string"), plain("integer"),
				arrayOf(anyOf(plain("string"), plain("integer"))))
		},
		// Duration: "30s"/"5m"/"2h" string, or the deprecated bare-number
		// (minutes) form accepted by Duration.UnmarshalText.
		reflect.TypeOf(config.Duration(0)): func() *jsonschema.Schema {
			s := anyOf(plain("string"), plain("integer"))
			s.Description = "Duration, e.g. '30s', '5m', '2h'. A bare number is the deprecated minutes form."
			s.Examples = []any{"30s", "1h"}

			return s
		},
		// ECS masks: an unquoted number, or its quoted-string form. Both go
		// through (ECSv4Mask/ECSv6Mask).UnmarshalText, so the schema must
		// accept the string form too.
		reflect.TypeOf(config.ECSv4Mask(0)): func() *jsonschema.Schema {
			return anyOf(plain("integer"), plain("string"))
		},
		reflect.TypeOf(config.ECSv6Mask(0)): func() *jsonschema.Schema {
			return anyOf(plain("integer"), plain("string"))
		},
		// QTypeSet is built from a YAML list of query-type names; the names are
		// exactly dns.StringToType's keys (case-sensitive), so an enum is exact.
		reflect.TypeOf(config.QTypeSet(nil)): func() *jsonschema.Schema {
			return arrayOf(enumStringSchema(qtypeNames()))
		},
		// minTlsServeVersion: "1.3" string or unquoted 1.3 number.
		reflect.TypeOf(config.TLSVersion(0)): func() *jsonschema.Schema {
			return anyOf(enumStringSchema(config.TLSVersionNames()), plain("number"))
		},
		// A bootstrap entry, or a list of them.
		reflect.TypeOf(config.BootstrapDNS(nil)): func() *jsonschema.Schema {
			return anyOf(bootstrappedUpstreamSchema(), arrayOf(bootstrappedUpstreamSchema()))
		},
		reflect.TypeOf(config.BootstrappedUpstream{}): bootstrappedUpstreamSchema,
		// conditional.mapping: domain -> comma-separated upstream string.
		reflect.TypeOf(config.ConditionalUpstreamMapping{}): func() *jsonschema.Schema {
			return openMap(plain("string"))
		},
		// customDNS.mapping: domain -> IP string or list of IP strings.
		reflect.TypeOf(config.CustomDNSMapping(nil)): func() *jsonschema.Schema {
			return openMap(anyOf(plain("string"), arrayOf(plain("string"))))
		},
	}
}

// makeMapper returns the Reflector.Mapper combining all registries. It MUST
// return a fresh *Schema on every call: invopop inlines the returned pointer at
// each use site (DoNotReference), so a shared pointer would let one field's
// mutation (e.g. flattenDeprecated, applyDefaults) leak into all others.
func makeMapper() func(reflect.Type) *jsonschema.Schema {
	enums := enumNames()
	strs := stringForms()
	complexes := complexForms()

	return func(t reflect.Type) *jsonschema.Schema {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}

		if ctor, ok := complexes[t]; ok {
			return ctor()
		}

		if names, ok := enums[t]; ok {
			return enumStringSchema(names)
		}

		if spec, ok := strs[t]; ok {
			return stringSchema(spec.description, spec.examples...)
		}

		return nil
	}
}

// applyDefaults walks the schema and the Go type in parallel, copying each
// field's `default:"..."` tag into the schema property's Default.
func applyDefaults(s *jsonschema.Schema, t reflect.Type) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct || s == nil || s.Properties == nil {
		return
	}

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)

		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			// embedded / inline struct: recurse with the same schema node
			if f.Anonymous {
				applyDefaults(s, f.Type)
			}

			continue
		}

		prop, ok := s.Properties.Get(name)
		if !ok {
			continue
		}

		if def, hasDef := f.Tag.Lookup("default"); hasDef {
			prop.Default = typedDefault(def, prop.Type)
		}

		applyDefaults(prop, f.Type) // recurse into nested structs
	}
}

// typedDefault converts a raw `default:"..."` tag into the JSON scalar matching
// the property's declared schema type, so a bool/int/float field yields
// `false`/`4`/`1.5` rather than the string "false"/"4"/"1.5". Enums and the
// custom string-scalars (Duration, TLSVersion, ECS masks) have schema type
// "string" or anyOf (empty Type), so they keep the string form. Any parse
// failure falls back to the string, never dropping the default.
func typedDefault(def, schemaType string) any {
	switch schemaType {
	case "boolean":
		if b, err := strconv.ParseBool(def); err == nil {
			return b
		}
	case "integer":
		if n, err := strconv.ParseInt(def, 10, 64); err == nil {
			return n
		}
	case "number":
		if f, err := strconv.ParseFloat(def, 64); err == nil {
			return f
		}
	}

	return def
}

// markDeprecated walks the schema and Go type in parallel, marking the fields
// of every inline `Deprecated` struct as deprecated. invopop flattens these
// `yaml:",inline"` blocks into their parent's properties (so blocky still
// accepts the keys) but does not carry the deprecation, so editors wouldn't
// strike them through. This covers the nested blocks (Blocking, HostsFile);
// the top-level Config.Deprecated is also re-marked here, idempotently with
// flattenDeprecated.
func markDeprecated(s *jsonschema.Schema, t reflect.Type) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct || s == nil || s.Properties == nil {
		return
	}

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)

		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")

		// Inline Deprecated struct: its fields are flattened into THIS node.
		if name == "" && f.Name == "Deprecated" {
			markFieldsDeprecated(s, f.Type)

			continue
		}

		if name == "" || name == "-" {
			if f.Anonymous {
				markDeprecated(s, f.Type)
			}

			continue
		}

		if prop, ok := s.Properties.Get(name); ok {
			markDeprecated(prop, f.Type) // recurse into nested structs
		}
	}
}

// markFieldsDeprecated marks each yaml-named field of struct type t as
// deprecated in schema node s (where the inline block was flattened).
func markFieldsDeprecated(s *jsonschema.Schema, t reflect.Type) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return
	}

	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			continue
		}

		if prop, ok := s.Properties.Get(name); ok {
			prop.Deprecated = true
		}
	}
}

// enumDescriptioner is implemented by every go-enum type through the generated
// EnumDescriptions() method (see tools/schemagen/templates/enum_description.tmpl).
// It returns each value's description, taken verbatim from the `ENUM(...)`
// comments — the single source of truth.
type enumDescriptioner interface {
	EnumDescriptions() map[string]string
}

// applyEnumDescriptions walks the schema and Go type in parallel, appending a
// per-value markdown legend to the `description` of every property whose enum
// type provides EnumDescriptions(). Only values present in the generated `enum`
// are rendered, so a description for a removed value is simply dropped.
func applyEnumDescriptions(s *jsonschema.Schema, t reflect.Type) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if s == nil {
		return
	}

	if ed, ok := reflect.New(t).Elem().Interface().(enumDescriptioner); ok {
		if legend := ed.EnumDescriptions(); len(legend) > 0 && len(s.Enum) > 0 {
			s.Description = withEnumLegend(s.Description, legend, s.Enum)
		}

		return
	}

	if t.Kind() != reflect.Struct || s.Properties == nil {
		return
	}

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)

		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			if f.Anonymous {
				applyEnumDescriptions(s, f.Type)
			}

			continue
		}

		if prop, ok := s.Properties.Get(name); ok {
			applyEnumDescriptions(prop, f.Type)
		}
	}
}

// withEnumLegend appends a `- ` + "`value`: description" bullet per enum value
// (in enum order) to an existing description.
func withEnumLegend(existing string, legend map[string]string, enum []any) string {
	var b strings.Builder

	if existing != "" {
		b.WriteString(existing)
		b.WriteString("\n\n")
	}

	for _, e := range enum {
		v, ok := e.(string)
		if !ok {
			continue
		}

		if d, ok := legend[v]; ok {
			fmt.Fprintf(&b, "- `%s`: %s\n", v, d)
		}
	}

	return strings.TrimRight(b.String(), "\n")
}

// flattenDeprecated reflects Config's named `yaml:",inline"` Deprecated struct
// (which invopop does NOT flatten automatically — it only flattens embedded
// fields) and merges its fields into the root schema as deprecated top-level
// properties. yaml.v2 inlines them, so they are valid top-level keys; this
// keeps the schema a superset of what blocky accepts and lets editors strike
// them through.
func flattenDeprecated(r *jsonschema.Reflector, root *jsonschema.Schema) {
	depField, ok := reflect.TypeOf(config.Config{}).FieldByName("Deprecated")
	if !ok {
		return
	}

	depSchema := r.Reflect(reflect.New(depField.Type).Interface())

	holder := resolvePropsHolder(depSchema)
	if holder == nil || holder.Properties == nil || root.Properties == nil {
		return
	}

	for pair := holder.Properties.Oldest(); pair != nil; pair = pair.Next() {
		pair.Value.Deprecated = true
		root.Properties.Set(pair.Key, pair.Value)
	}
}

// resolvePropsHolder returns the schema node that actually holds Properties,
// following a top-level $ref into Definitions if invopop referenced it.
func resolvePropsHolder(s *jsonschema.Schema) *jsonschema.Schema {
	if s == nil {
		return nil
	}

	if s.Properties != nil && s.Properties.Len() > 0 {
		return s
	}

	if s.Ref != "" && s.Definitions != nil {
		name := s.Ref[strings.LastIndex(s.Ref, "/")+1:]
		if def, ok := s.Definitions[name]; ok {
			return def
		}
	}

	return s
}
