// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

const apiSpecGolden = "testdata/api_spec_contract.golden"

// specFiles are the OpenAPI documents that define the REST surface. The first
// is an upstream file carrying fork edits — the kind most at risk of being
// reverted wholesale by a merge. The second is Blockasaurus-only.
var specFiles = []string{
	"../docs/api/openapi.yaml",
	"../docs/api/openapi-config.yaml",
}

// httpMethods are the keys under a path item that denote an operation;
// everything else there (parameters, summary, servers, $ref, x-* extensions)
// is not one and is skipped.
var httpMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

// TestAPISpecContract locks the shape of the REST API as declared in the
// OpenAPI specs: every operation, the schema each one exchanges in its request
// and responses, and every component schema down to property names, types,
// array item types, enum members and required fields.
//
// TestAPIContract covers routing — which URLs exist and what guards them.
// This covers payloads. Together they are what "don't change the API
// contract" means in practice, because the Svelte UI in web/ui depends on
// both and a merge can break either one independently.
//
// Deliberately not a checksum of the files: the spec carries prose
// (descriptions, summaries, tags, branding) that will legitimately change
// during an upstream merge, and a guard that cries wolf on a reworded
// description gets regenerated without being read.
//
// What it still does not reach, so nobody trusts it further than it goes:
//
//   - Handler behavior. This reads the spec, not the code. Nothing here proves
//     a handler actually honors the schema it advertises.
//   - components.parameters and components.responses as declared. Their use is
//     recorded where an operation references one by name, but the contents
//     behind that name are not.
//   - Anything the spec does not say. An undocumented field the UI relies on
//     is invisible here by construction.
func TestAPISpecContract(t *testing.T) {
	sections := make([]string, 0, len(specFiles))

	for _, path := range specFiles {
		spec, err := loadSpec(path)
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}

		lines := append([]string{"### " + strings.TrimPrefix(path, "../")}, specOperations(spec)...)
		lines = append(lines, specSchemas(spec)...)

		sections = append(sections, strings.Join(lines, "\n"))
	}

	assertGolden(t, apiSpecGolden, strings.Join(sections, "\n\n")+"\n",
		"OpenAPI contract changed",
		"go test ./server -run TestAPISpecContract -update-api-contract")
}

type openAPISpec struct {
	Paths      map[string]map[string]specOperation `yaml:"paths"`
	Components struct {
		Schemas map[string]specType `yaml:"schemas"`
	} `yaml:"components"`
}

// specOperation is one operation under a path item, together with the schemas
// it exchanges. Recording the wiring matters as much as recording the schemas:
// a merge that re-points PUT /custom-dns/{id} from CustomDNSEntryInput to
// CustomDNSEntry changes the contract without touching either schema.
type specOperation struct {
	OperationID string              `yaml:"operationId"`
	Parameters  []specParameter     `yaml:"parameters"`
	RequestBody specBody            `yaml:"requestBody"`
	Responses   map[string]specBody `yaml:"responses"`
}

// specParameter is one path, query or header parameter. The UI builds request
// URLs from these, so a query parameter losing its enum or changing its name
// breaks a caller just as surely as a renamed body field.
type specParameter struct {
	Ref      string   `yaml:"$ref"`
	Name     string   `yaml:"name"`
	In       string   `yaml:"in"`
	Required bool     `yaml:"required"`
	Schema   specType `yaml:"schema"`
}

// UnmarshalYAML tolerates path-item keys that are not operations. OpenAPI
// allows summary, description, servers, parameters and $ref as siblings of the
// HTTP methods; decoding any of those into this struct is a type error that
// would otherwise fail the whole load — and because loadSpec's error is fatal
// before assertGolden runs, -update-api-contract could not get you out of it
// either. Upstream owns openapi.yaml, so it may well add one mid-merge, which
// is the worst possible time for the payload guard to become unrunnable.
//
// Non-mappings are left zero here and dropped by the httpMethods filter in
// specOperations.
func (o *specOperation) UnmarshalYAML(unmarshal func(any) error) error {
	var probe map[string]any
	if err := unmarshal(&probe); err != nil {
		return nil //nolint:nilerr // not an operation; see doc comment
	}

	// Distinct type so this method is not inherited, which would recurse.
	type operation specOperation

	var decoded operation
	if err := unmarshal(&decoded); err != nil {
		return err
	}

	*o = specOperation(decoded)

	return nil
}

// specBody is a request body or a single response. Either may be a reference
// to components.responses rather than an inline content map.
type specBody struct {
	Ref     string                 `yaml:"$ref"`
	Content map[string]specContent `yaml:"content"`
}

type specContent struct {
	Schema specType `yaml:"schema"`
}

// specType is one schema node — a component schema, a property, or an array's
// item type. It is recursive because arrays and $refs are how the payloads
// that actually matter get described, and a guard that stopped at the top
// level would miss an array of strings becoming an array of integers.
type specType struct {
	Type                 specTypeName        `yaml:"type"`
	Format               string              `yaml:"format"`
	Ref                  string              `yaml:"$ref"`
	Nullable             bool                `yaml:"nullable"`
	Enum                 []any               `yaml:"enum"`
	Required             []string            `yaml:"required"`
	Items                *specType           `yaml:"items"`
	AdditionalProperties *specType           `yaml:"additionalProperties"`
	Properties           map[string]specType `yaml:"properties"`
	AllOf                []specType          `yaml:"allOf"`
	OneOf                []specType          `yaml:"oneOf"`
}

// UnmarshalYAML accepts the scalar forms a schema node can legally take —
// `additionalProperties: true` being the common one. A structured node we
// failed to model is a different matter and stays a hard error: it means this
// guard does not understand part of the contract it claims to lock, and
// silently recording nothing would be worse than failing.
func (t *specType) UnmarshalYAML(unmarshal func(any) error) error {
	// Distinct type so this method is not inherited, which would recurse.
	type schema specType

	var decoded schema
	if err := unmarshal(&decoded); err == nil {
		*t = specType(decoded)

		return nil
	}

	var scalar any
	if err := unmarshal(&scalar); err != nil {
		return err
	}

	switch scalar.(type) {
	case map[any]any, []any:
		return fmt.Errorf("unmodelled schema node: %T", scalar)
	}

	t.Type = specTypeName(fmt.Sprintf("%v", scalar))

	return nil
}

// specTypeName decodes OpenAPI's `type`, which is a single string in 3.0 but
// may be a list in 3.1 — `type: [string, "null"]` is how 3.1 spells what 3.0
// spelled `nullable: true`. Both specs here declare 3.1.1, so upstream
// adopting the list form must not break the load.
type specTypeName string

func (n *specTypeName) UnmarshalYAML(unmarshal func(any) error) error {
	var single string
	if err := unmarshal(&single); err == nil {
		*n = specTypeName(single)

		return nil
	}

	var multi []string
	if err := unmarshal(&multi); err != nil {
		return err
	}

	*n = specTypeName(strings.Join(multi, "|"))

	return nil
}

func loadSpec(path string) (*openAPISpec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var spec openAPISpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		return nil, err
	}

	return &spec, nil
}

func specOperations(spec *openAPISpec) []string {
	lines := make([]string, 0, len(spec.Paths))

	for path, item := range spec.Paths {
		for method, op := range item {
			if !httpMethods[strings.ToLower(method)] {
				continue
			}

			id := op.OperationID
			if id == "" {
				id = "(no operationId)"
			}

			lines = append(lines, fmt.Sprintf("op   %-7s %-45s %-28s params=[%s] req=%s resp=[%s]",
				strings.ToUpper(method), path, id, describeParameters(op.Parameters),
				describeBody(op.RequestBody), describeResponses(op.Responses)))
		}
	}

	sort.Strings(lines)

	return lines
}

// describeParameters renders an operation's parameters, sorted so the golden
// does not churn on a reordering that changes nothing.
func describeParameters(params []specParameter) string {
	parts := make([]string, 0, len(params))

	for _, p := range params {
		if p.Ref != "" {
			parts = append(parts, refName(p.Ref))

			continue
		}

		part := p.In + ":" + p.Name + ":" + describeType(p.Schema)
		if p.Required {
			part += "!"
		}

		parts = append(parts, part)
	}

	sort.Strings(parts)

	return strings.Join(parts, " ")
}

// describeBody names the schema a request body or response carries, per media
// type. "-" means no body is declared, which is itself part of the contract.
func describeBody(body specBody) string {
	if body.Ref != "" {
		return refName(body.Ref)
	}

	if len(body.Content) == 0 {
		return "-"
	}

	parts := make([]string, 0, len(body.Content))
	for media, content := range body.Content {
		parts = append(parts, media+":"+describeType(content.Schema))
	}

	sort.Strings(parts)

	return strings.Join(parts, ",")
}

func describeResponses(responses map[string]specBody) string {
	codes := make([]string, 0, len(responses))
	for code := range responses {
		codes = append(codes, code)
	}

	sort.Strings(codes)

	parts := make([]string, 0, len(codes))
	for _, code := range codes {
		parts = append(parts, code+":"+describeBody(responses[code]))
	}

	return strings.Join(parts, " ")
}

func specSchemas(spec *openAPISpec) []string {
	lines := make([]string, 0, len(spec.Components.Schemas))

	for name, schema := range spec.Components.Schemas {
		required := append([]string(nil), schema.Required...)
		sort.Strings(required)

		props := make([]string, 0, len(schema.Properties))

		for prop, def := range schema.Properties {
			props = append(props, prop+":"+describeType(def))
		}

		sort.Strings(props)

		lines = append(lines, fmt.Sprintf("type %-30s %s required=[%s] props=[%s]",
			name, describeType(schema), strings.Join(required, " "), strings.Join(props, " ")))
	}

	sort.Strings(lines)

	return lines
}

// describeType renders a schema node compactly and deterministically.
// Properties are rendered by the caller, so this describes the node itself:
// its type, an array's item type in <>, a map's value type in {}, enum
// members, and composition.
func describeType(t specType) string {
	if t.Ref != "" {
		return refName(t.Ref)
	}

	desc := string(t.Type)
	if t.Format != "" {
		desc += "/" + t.Format
	}

	if desc == "" {
		desc = "?"
	}

	if t.Items != nil {
		desc += "<" + describeType(*t.Items) + ">"
	}

	if t.AdditionalProperties != nil {
		desc += "{" + describeType(*t.AdditionalProperties) + "}"
	}

	if len(t.Enum) > 0 {
		desc += "=" + enumMembers(t.Enum)
	}

	if composed := describeAll(t.AllOf); composed != "" {
		desc += " allOf(" + composed + ")"
	}

	if composed := describeAll(t.OneOf); composed != "" {
		desc += " oneOf(" + composed + ")"
	}

	if t.Nullable {
		desc += " nullable"
	}

	return desc
}

func describeAll(types []specType) string {
	if len(types) == 0 {
		return ""
	}

	parts := make([]string, 0, len(types))
	for _, t := range types {
		parts = append(parts, describeType(t))
	}

	return strings.Join(parts, " ")
}

// enumMembers keeps declaration order: an enum's members are a set as far as
// validation goes, but reordering them is churn we would rather see than hide,
// and sorting would mask a value being replaced by one that sorts identically.
func enumMembers(values []any) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, fmt.Sprintf("%v", v))
	}

	return "[" + strings.Join(parts, "|") + "]"
}

// refName shortens "#/components/schemas/ClientGroup" to "ref:ClientGroup".
// The prefix is noise; the target is the contract.
func refName(ref string) string {
	return "ref:" + ref[strings.LastIndex(ref, "/")+1:]
}
