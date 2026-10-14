package stringcache

import (
	"math"
	"math/rand/v2"
	"slices"
	"testing"
)

const (
	hashSetOracleProbes = 10_000
	hashSetLargeSize    = 1_000_000
)

func TestHashSetMatchesMapOracle(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewPCG(3, 4))

	for _, n := range []int{0, 1, 2, 3, 4, 5, 1000, hashSetLargeSize} {
		keys := make([]uint64, n)
		oracle := make(map[uint64]struct{}, n)

		for i := range keys {
			keys[i] = rng.Uint64()
			oracle[keys[i]] = struct{}{}
		}

		set := newHashSet(slices.Clone(keys))

		if set.len() != len(oracle) {
			t.Fatalf("n=%d: len() = %d, want %d", n, set.len(), len(oracle))
		}

		for _, key := range keys {
			if !set.contains(key) {
				t.Fatalf("n=%d: missing stored key %x", n, key)
			}
		}

		for range hashSetOracleProbes {
			probe := rng.Uint64()
			if _, want := oracle[probe]; set.contains(probe) != want {
				t.Fatalf("n=%d: contains(%x) = %v, want %v", n, probe, !want, want)
			}
		}
	}
}

func TestHashSetEmptyContainsNothing(t *testing.T) {
	t.Parallel()

	for name, set := range map[string]hashSet{"zero value": {}, "nil keys": newHashSet(nil)} {
		for _, probe := range []uint64{0, 1, math.MaxUint64} {
			if set.contains(probe) {
				t.Errorf("%s: contains(%x) = true", name, probe)
			}
		}

		if set.len() != 0 {
			t.Errorf("%s: len() = %d, want 0", name, set.len())
		}
	}
}

func TestHashSetSingleKey(t *testing.T) {
	t.Parallel()

	for _, key := range []uint64{0, 1, math.MaxUint64} {
		set := newHashSet([]uint64{key})

		if set.len() != 1 || !set.contains(key) {
			t.Errorf("key %x: len() = %d, contains = %v", key, set.len(), set.contains(key))
		}

		for _, other := range []uint64{key + 1, key - 1} {
			if set.contains(other) {
				t.Errorf("key %x: contains(%x) = true for absent key", key, other)
			}
		}
	}
}

func TestHashSetDeduplicates(t *testing.T) {
	t.Parallel()

	set := newHashSet([]uint64{7, 7, 3, 7, 3})

	if set.len() != 2 || !set.contains(3) || !set.contains(7) || set.contains(5) {
		t.Errorf("unexpected set %v", set.keys)
	}
}

// Keys on both sides of every power of two cover the edges of the index buckets
// whatever the bucket count is, together with the first and the last possible key.
func TestHashSetFindsKeysAtBucketBoundaries(t *testing.T) {
	t.Parallel()

	// Two edge keys, and two keys per bit position below.
	keys := make([]uint64, 0, 2+2*hashBits)
	keys = append(keys, 0, math.MaxUint64)
	// One absent probe per bit position, plus the top edge.
	absent := make([]uint64, 0, 1+hashBits)
	absent = append(absent, math.MaxUint64-1)

	for shift := range uint(hashBits) {
		boundary := uint64(1) << shift

		// boundary-1 and boundary are stored, boundary+1 is not.
		keys = append(keys, boundary-1, boundary)
		absent = append(absent, boundary+1)
	}

	set := newHashSet(slices.Clone(keys))

	for _, key := range keys {
		if !set.contains(key) {
			t.Errorf("missing stored key %x", key)
		}
	}

	for _, probe := range absent {
		if slices.Contains(keys, probe) {
			continue // a neighbouring boundary stores it
		}

		if set.contains(probe) {
			t.Errorf("contains(%x) = true for absent key", probe)
		}
	}
}

// Many keys share their top bits, so they crowd into one bucket.
func TestHashSetFindsKeysCrowdedInOneBucket(t *testing.T) {
	t.Parallel()

	const (
		topBit  = uint64(1) << 63
		crowded = 64
	)

	keys := make([]uint64, 0, crowded)
	for i := range uint64(crowded) {
		keys = append(keys, topBit|i)
	}

	set := newHashSet(slices.Clone(keys))

	for _, key := range keys {
		if !set.contains(key) {
			t.Errorf("missing stored key %x", key)
		}
	}

	for _, probe := range []uint64{0, topBit - 1, topBit | crowded, math.MaxUint64} {
		if set.contains(probe) {
			t.Errorf("contains(%x) = true for absent key", probe)
		}
	}
}
