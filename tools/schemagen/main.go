// Command schemagen generates docs/config.schema.json from the blocky config
// structs. Run via `go generate ./config/...` (cwd: ./config).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/0xERR0R/blocky/config"
	"github.com/invopop/jsonschema"
)

const (
	outPath  = "../docs/config.schema.json" // relative to ./config (go:generate cwd)
	dirPerm  = 0o755
	filePerm = 0o644
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "schemagen:", err)
		os.Exit(1)
	}
}

func run() error {
	r := &jsonschema.Reflector{
		FieldNameTag: "yaml", // read yaml tags, not json
		// AllowAdditionalProperties stays false => additionalProperties:false,
		// matching yaml.UnmarshalStrict's unknown-key rejection.
		// RequiredFromJSONSchemaTags=true makes only `jsonschema:"required"`
		// fields required; blocky tags none, so nothing is required (a config
		// with all defaults is valid). The default would require every field.
		RequiredFromJSONSchemaTags: true,
		// DoNotReference inlines the whole tree so the defaults/deprecated
		// walks below can see nested properties (config has no recursive types).
		DoNotReference: true,
	}
	r.Mapper = makeMapper()

	// Doc comments -> descriptions. cwd is ./config at generate time.
	if err := r.AddGoComments("github.com/0xERR0R/blocky/config", "."); err != nil {
		return fmt.Errorf("add go comments: %w", err)
	}

	schema := r.Reflect(&config.Config{})

	flattenDeprecated(r, schema)
	applyDefaults(schema, reflect.TypeOf(config.Config{}))
	markDeprecated(schema, reflect.TypeOf(config.Config{}))
	// Enum value descriptions come from the generated EnumDescriptions() methods,
	// which carry the go-enum `ENUM(...)` comments (the single source of truth).
	applyEnumDescriptions(schema, reflect.TypeOf(config.Config{}))

	out, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal schema: %w", err)
	}

	out = append(out, '\n')

	if err := os.MkdirAll(filepath.Dir(outPath), dirPerm); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	return os.WriteFile(outPath, out, filePerm)
}
