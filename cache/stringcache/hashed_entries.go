package stringcache

import "slices"

// hashedEntries collects the hashes of a factory's entries, all taken with the
// same seed, and builds the hashSet from them. build is idempotent, so a
// factory can be asked to create its cache more than once.
type hashedEntries struct {
	seed uint64
	keys []uint64
	// built is the set handed out by the last build. It owns keys until add
	// is called again.
	built *hashSet
}

func newHashedEntries() hashedEntries {
	return hashedEntries{seed: newSeed()}
}

func (e *hashedEntries) add(hash uint64) {
	if e.built != nil {
		// keys belong to the set already handed out: don't append to them in place.
		e.keys = slices.Clone(e.keys)
		e.built = nil
	}

	e.keys = append(e.keys, hash)
}

func (e *hashedEntries) build() hashSet {
	if e.built == nil {
		set := newHashSet(e.keys)
		e.keys = set.keys
		e.built = &set
	}

	return *e.built
}
