package stringcache

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
	"unicode/utf8"
)

// Blocklist entries are stored as 64-bit hashes instead of text: FNV-1a, whose
// output is passed through the murmur3 fmix64 finalizer so that the top bits
// (which index the hashSet) are uniformly distributed.
const (
	fnvOffset64 uint64 = 14695981039346656037
	fnvPrime64  uint64 = 1099511628211

	fmixMultiplier1 uint64 = 0xff51afd7ed558ccd
	fmixMultiplier2 uint64 = 0xc4ceb9fe1a85ec53
	fmixShift              = 33

	asciiCaseBit byte = 'a' - 'A'
)

// newSeed returns a random seed that is mixed into every hash. A fresh one is
// chosen each time a list is loaded. FNV-1a collisions can be forged cheaply
// when the hash is known, so without an unpredictable seed an attacker could
// craft a domain that collides with an allowlist entry. FNV-1a with a secret
// basis plus fmix64 is not a vetted keyed hash: the seed makes crafting
// collisions impractical, not impossible.
func newSeed() uint64 {
	var buf [8]byte

	rand.Read(buf[:]) // never fails: on error it crashes the program (crypto/rand docs, Go 1.24+)

	return binary.LittleEndian.Uint64(buf[:])
}

// mix is the bijective murmur3 fmix64 finalizer.
func mix(h uint64) uint64 {
	h ^= h >> fmixShift
	h *= fmixMultiplier1
	h ^= h >> fmixShift
	h *= fmixMultiplier2
	h ^= h >> fmixShift

	return h
}

func fnvBasis(seed uint64) uint64 {
	return fnvOffset64 ^ seed
}

func fnvStep(h uint64, b byte) uint64 {
	return (h ^ uint64(b)) * fnvPrime64
}

func lowerASCII(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b | asciiCaseBit
	}

	return b
}

// hashFold hashes s as strings.ToLower(s) would be hashed by hashRaw, but
// without allocating for ASCII input.
func hashFold(seed uint64, s string) uint64 {
	h := fnvBasis(seed)

	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return hashRaw(seed, strings.ToLower(s))
		}

		h = fnvStep(h, lowerASCII(s[i]))
	}

	return mix(h)
}

// hashRaw hashes the bytes of s as they are.
func hashRaw(seed uint64, s string) uint64 {
	h := fnvBasis(seed)

	for i := range len(s) {
		h = fnvStep(h, s[i])
	}

	return mix(h)
}

// hashReversed hashes the bytes of s from last to first, as they are. In this
// order every label-boundary suffix of a domain is a prefix of the stream, so
// a lookup can hash a query once and probe each suffix on the way.
func hashReversed(seed uint64, s string) uint64 {
	h := fnvBasis(seed)

	for i := len(s) - 1; i >= 0; i-- {
		h = fnvStep(h, s[i])
	}

	return mix(h)
}
