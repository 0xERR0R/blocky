package stringcache

import (
	"math"
	"math/bits"
	"slices"
)

const (
	// hashSetKeysPerBucket sizes the index: it has 2^bits.Len(n/hashSetKeysPerBucket)
	// buckets, so a bucket holds between 2 and 4 keys on average.
	hashSetKeysPerBucket = 4
	hashBits             = 64
)

// hashSet is an immutable set of uniformly distributed 64-bit hashes: sorted
// keys plus an index from the top bits of a hash to the keys sharing them.
// A lookup reads one or two cache lines and compares a few keys.
type hashSet struct {
	keys []uint64 // sorted, unique
	// idx[p] is the position of the first key whose top bits are >= p, so the
	// keys with top bits p are keys[idx[p]:idx[p+1]]. len(idx) == 1<<bits + 1.
	idx   []uint32
	shift uint // hashBits minus the number of index bits
}

// newHashSet takes ownership of keys: it sorts and deduplicates them in place.
func newHashSet(keys []uint64) hashSet {
	slices.Sort(keys)
	keys = slices.Compact(keys)

	// Compact leaves the append slack and the room taken by duplicates behind;
	// copy to an exactly sized slice so that they can be freed.
	if cap(keys) > len(keys) {
		keys = slices.Clone(keys)
	}

	// idx holds positions as uint32; no blocklist comes anywhere near 4G entries.
	if uint64(len(keys)) >= math.MaxUint32 {
		panic("stringcache: too many entries for a hashSet")
	}

	indexBits := max(1, bits.Len(uint(len(keys)/hashSetKeysPerBucket)))
	shift := uint(hashBits - indexBits)
	idx := make([]uint32, 1<<indexBits+1)

	pos := 0
	for prefix := range idx {
		for pos < len(keys) && keys[pos]>>shift < uint64(prefix) {
			pos++
		}

		idx[prefix] = uint32(pos)
	}

	return hashSet{keys: keys, idx: idx, shift: shift}
}

func (s hashSet) len() int {
	return len(s.keys)
}

func (s hashSet) contains(h uint64) bool {
	if len(s.keys) == 0 {
		return false
	}

	prefix := h >> s.shift

	return slices.Contains(s.keys[s.idx[prefix]:s.idx[prefix+1]], h)
}
