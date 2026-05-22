// Package schema embeds the generated config JSON schema and validates
// YAML config documents against it.
package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v2"

	"github.com/0xERR0R/blocky/docs"
)

// JSON is the embedded config JSON schema, generated into docs/ and embedded
// by the docs package (so it is also published on the docs site and can be
// served by the HTTP server).
//
//nolint:gochecknoglobals
var JSON = docs.ConfigSchema

// Error is a single schema validation finding with a config field path.
type Error struct {
	Path    string
	Message string
}

func (e Error) String() string {
	if e.Path == "" {
		return e.Message
	}

	return e.Path + ": " + e.Message
}

//nolint:gochecknoglobals
var compiled = mustCompile()

func mustCompile() *jsonschema.Schema {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(JSON))
	if err != nil {
		panic(fmt.Errorf("embedded config schema is not valid JSON: %w", err))
	}

	c := jsonschema.NewCompiler()
	if err := c.AddResource("config.schema.json", doc); err != nil {
		panic(fmt.Errorf("add schema resource: %w", err))
	}

	s, err := c.Compile("config.schema.json")
	if err != nil {
		panic(fmt.Errorf("compile config schema: %w", err))
	}

	return s
}

// ValidateYAML validates a raw YAML config document against the schema and
// returns field-path findings. A nil/empty result means "matches schema".
// A non-nil error means the YAML itself could not be parsed.
func ValidateYAML(data []byte) ([]Error, error) {
	instance, err := yamlToJSONValue(data)
	if err != nil {
		return nil, err
	}

	if err := compiled.Validate(instance); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			return flatten(ve), nil
		}

		return []Error{{Message: err.Error()}}, nil
	}

	return nil, nil
}

// yamlToJSONValue parses YAML and round-trips it through JSON so the result
// uses JSON-native Go types (string, float64, bool, map[string]any, []any),
// which is what the validator expects. yaml.v2 otherwise yields
// map[interface{}]interface{} and int values.
func yamlToJSONValue(data []byte) (interface{}, error) {
	var raw interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	jsonBytes, err := json.Marshal(toStringKeyed(raw))
	if err != nil {
		return nil, fmt.Errorf("normalize config to JSON: %w", err)
	}

	return jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
}

// toStringKeyed converts yaml.v2's map[interface{}]interface{} into
// map[string]interface{} recursively so it can be JSON-marshaled.
func toStringKeyed(v interface{}) interface{} {
	switch t := v.(type) {
	case map[interface{}]interface{}:
		m := make(map[string]interface{}, len(t))
		for k, val := range t {
			m[fmt.Sprintf("%v", k)] = toStringKeyed(val)
		}

		return m
	case []interface{}:
		s := make([]interface{}, len(t))
		for i, val := range t {
			s[i] = toStringKeyed(val)
		}

		return s
	default:
		return v
	}
}

// flatten walks the v6 validation error tree and returns one Error per leaf
// (the most specific failures), sorted by path for deterministic output.
func flatten(ve *jsonschema.ValidationError) []Error {
	var out []Error

	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			path := strings.Join(e.InstanceLocation, ".")

			msg := e.Error()
			// Drop the leading "jsonschema ... at '<loc>':" prefix so the Path
			// carries the location and Message stays readable.
			if i := strings.LastIndex(msg, ": "); i != -1 {
				msg = msg[i+2:]
			}

			out = append(out, Error{Path: path, Message: strings.TrimSpace(msg)})

			return
		}

		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })

	return out
}
