package config

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
