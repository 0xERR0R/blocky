package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v2"
)

// mergeMaps deep-merges src into dst and returns the result: keys whose
// values are mappings on both sides merge recursively; any other collision
// (scalar, list, explicit null, or type mismatch) resolves to the src value
// (last wins). dst is modified in place; pass nil to start fresh.
func mergeMaps(dst, src map[interface{}]interface{}) map[interface{}]interface{} {
	if dst == nil {
		dst = make(map[interface{}]interface{}, len(src))
	}

	for key, srcVal := range src {
		dstMap, dstIsMap := dst[key].(map[interface{}]interface{})
		srcMap, srcIsMap := srcVal.(map[interface{}]interface{})

		if dstIsMap && srcIsMap {
			dst[key] = mergeMaps(dstMap, srcMap)

			continue
		}

		dst[key] = srcVal
	}

	return dst
}

// decodeYAMLDocuments strict-decodes every YAML document in data into a
// generic map. Strict mode keeps duplicate keys within a single document an
// error. Empty documents (e.g. comment-only files) are skipped.
func decodeYAMLDocuments(data []byte) ([]map[interface{}]interface{}, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.SetStrict(true)

	var docs []map[interface{}]interface{}

	for {
		var raw interface{}

		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, err
		}

		if raw == nil {
			// empty document
			continue
		}

		doc, ok := raw.(map[interface{}]interface{})
		if !ok {
			return nil, fmt.Errorf("top level of a config document must be a mapping, got %T", raw)
		}

		docs = append(docs, doc)
	}

	return docs, nil
}

// configFile is one YAML file collected from a config folder.
type configFile struct {
	path string
	data []byte
}

// mergeConfigFiles structurally merges config files in the given order and
// returns the merged document marshaled back to YAML. Returns nil when no
// file contains any document.
func mergeConfigFiles(files []configFile) ([]byte, error) {
	var merged map[interface{}]interface{}

	for _, file := range files {
		docs, err := decodeYAMLDocuments(file.data)
		if err != nil {
			return nil, fmt.Errorf("can't parse config file %s: %w", file.path, err)
		}

		for _, doc := range docs {
			merged = mergeMaps(merged, doc)
		}
	}

	if merged == nil {
		return nil, nil
	}

	out, err := yaml.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("can't marshal merged config: %w", err)
	}

	return out, nil
}
