package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/0xERR0R/blocky/config/schema"
	yaml "gopkg.in/yaml.v3"
)

// configFile is one YAML file collected from a config folder.
type configFile struct {
	path string
	data []byte
}

// mergeConfigFiles structurally merges config files in the given order and
// returns the merged document marshaled back to YAML. Returns nil when no
// file contains any document.
//
// Files are parsed into yaml.v3 node trees, which preserve each scalar's
// literal text and quoting style. The merged tree is re-encoded and handed to
// the strict yaml.v2 config unmarshal unchanged, so a folder config decodes a
// scalar exactly as a single-file config would (e.g. `1.0` stays `1.0`, not
// `1`; `yes` stays plain `yes`; `0700` stays `0700`).
func mergeConfigFiles(files []configFile) ([]byte, error) {
	var merged *yaml.Node

	for _, file := range files {
		docs, err := decodeYAMLDocuments(file.data)
		if err != nil {
			return nil, fmt.Errorf("can't parse config file %s: %w", file.path, err)
		}

		for _, doc := range docs {
			if merged == nil {
				merged = doc

				continue
			}

			merged = mergeMappingNodes(merged, doc)
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

// decodeYAMLDocuments decodes every YAML document in data into a yaml.v3 node
// tree and returns each document's top-level mapping node. Per document it
// expands within-file anchors/aliases (stripping anchor names so none survive
// into the merged document), rejects duplicate keys at every level, and
// rejects a non-mapping top level. Empty and null documents (comment-only
// files, bare `---`) are skipped.
func decodeYAMLDocuments(data []byte) ([]*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))

	var docs []*yaml.Node

	for {
		var doc yaml.Node

		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			// e.g. yaml.v3 reports `unknown anchor 'x' referenced` here.
			return nil, err
		}

		// A document node wraps its single root in Content. An empty document
		// (comment-only file) has no content at all.
		if len(doc.Content) == 0 {
			continue
		}

		root, err := expandAliases(doc.Content[0])
		if err != nil {
			return nil, err
		}

		// Skip null documents (bare `---` or an explicit `null`).
		if root.Tag == nullTag {
			continue
		}

		if root.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("top level of a config document must be a mapping, got %s", nodeKindName(root))
		}

		if err := checkDuplicateKeys(root); err != nil {
			return nil, err
		}

		docs = append(docs, root)
	}

	return docs, nil
}

const nullTag = "!!null"

// expandAliases returns a deep, alias-free, anchor-free copy of node: every
// alias is replaced by a copy of its anchor target and every Anchor field is
// cleared. This bakes within-file anchor semantics into the tree before
// merging, so no anchor name can survive to collide across files.
//
// It is cycle-safe: re-entering a node already on the resolution stack (a
// self- or mutually-referential anchor such as `a: &x [*x]`) is reported as an
// error instead of recursing forever.
func expandAliases(node *yaml.Node) (*yaml.Node, error) {
	return resolveNode(node, map[*yaml.Node]bool{})
}

func resolveNode(node *yaml.Node, onStack map[*yaml.Node]bool) (*yaml.Node, error) {
	if node.Kind == yaml.AliasNode {
		if node.Alias == nil {
			return nil, fmt.Errorf("alias %q has no anchor target", node.Value)
		}

		return resolveNode(node.Alias, onStack)
	}

	if onStack[node] {
		name := node.Anchor
		if name == "" {
			name = node.Value
		}

		return nil, fmt.Errorf("anchor cycle detected at %q", name)
	}

	onStack[node] = true
	defer delete(onStack, node)

	clone := *node
	clone.Anchor = ""
	clone.Alias = nil

	if node.Content != nil {
		clone.Content = make([]*yaml.Node, len(node.Content))

		for i, child := range node.Content {
			resolved, err := resolveNode(child, onStack)
			if err != nil {
				return nil, err
			}

			clone.Content[i] = resolved
		}
	}

	return &clone, nil
}

// checkDuplicateKeys rejects duplicate scalar keys within any mapping in the
// tree, mirroring yaml.v2's strict-mode wording. yaml.v2 no longer sees the
// raw documents (it only parses the re-encoded merge), so this restores that
// safety net. Non-scalar keys (legal YAML, absent from blocky configs) are not
// matched.
func checkDuplicateKeys(node *yaml.Node) error {
	switch node.Kind {
	case yaml.MappingNode:
		seen := make(map[string]bool, len(node.Content)/2)

		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]

			if key.Kind == yaml.ScalarNode {
				if seen[key.Value] {
					return fmt.Errorf("line %d: key %q already set in map", key.Line, key.Value)
				}

				seen[key.Value] = true
			}

			if err := checkDuplicateKeys(value); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := checkDuplicateKeys(child); err != nil {
				return err
			}
		}
	case yaml.DocumentNode, yaml.ScalarNode, yaml.AliasNode:
		// Leaves and document wrappers carry no nested mapping to inspect; the
		// resolved tree has no aliases left anyway.
	}

	return nil
}

// mergeMappingNodes deep-merges src into dst and returns the result: keys
// matched by scalar key value whose values are mappings on both sides merge
// recursively; any other collision (scalar, sequence, explicit null, or kind
// mismatch) resolves to the src value (last wins). Keys present in only one
// side are kept; new src keys are appended after dst's, preserving first-seen
// key order. dst is modified in place.
func mergeMappingNodes(dst, src *yaml.Node) *yaml.Node {
	for i := 0; i+1 < len(src.Content); i += 2 {
		srcKey := src.Content[i]
		srcVal := src.Content[i+1]

		dstValIdx := mappingValueIndex(dst, srcKey)
		if dstValIdx < 0 {
			dst.Content = append(dst.Content, srcKey, srcVal)

			continue
		}

		dstVal := dst.Content[dstValIdx]
		if dstVal.Kind == yaml.MappingNode && srcVal.Kind == yaml.MappingNode {
			dst.Content[dstValIdx] = mergeMappingNodes(dstVal, srcVal)

			continue
		}

		dst.Content[dstValIdx] = srcVal
	}

	return dst
}

// mappingValueIndex returns the index of the value node in mapping whose key
// matches the given scalar key by value, or -1. Non-scalar keys never match.
func mappingValueIndex(mapping, key *yaml.Node) int {
	if key.Kind != yaml.ScalarNode {
		return -1
	}

	for i := 0; i+1 < len(mapping.Content); i += 2 {
		candidate := mapping.Content[i]
		if candidate.Kind == yaml.ScalarNode && candidate.Value == key.Value {
			return i + 1
		}
	}

	return -1
}

// nodeKindName gives a human-readable name for a node's kind, used in the
// non-mapping top-level error.
func nodeKindName(node *yaml.Node) string {
	switch node.Kind {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return "unknown"
	}
}

// attributeToSources maps a post-merge unmarshal failure back to the source
// files using per-file schema validation, so the error names the offending
// file instead of the merged document the user never sees. It only ever adds
// information; the original error is always kept.
func attributeToSources(err error, sources []configFile) error {
	var lines []string

	for _, src := range sources {
		if schemaErrs, sErr := schema.ValidateYAML(src.data); sErr == nil && len(schemaErrs) > 0 {
			for _, e := range schemaErrs {
				lines = append(lines, fmt.Sprintf("  - %s: %s", src.path, e.String()))
			}
		}
	}

	if len(lines) == 0 {
		return err
	}

	return fmt.Errorf("%w\nfindings per source file:\n%s", err, strings.Join(lines, "\n"))
}
