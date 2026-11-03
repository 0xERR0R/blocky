package stringcache

import (
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

const testSeed uint64 = 0x9e3779b97f4a7c15

const (
	randomInputs    = 500 // random strings fed to the case-folding property
	maxRandomLength = 20  // in alphabet symbols
	longInputLabels = 200 // repetitions of "Ab." in the long input

	mixSamples      = 1 << 16
	topBitsPerIndex = 8 // top hash bits that index a hashSet bucket
)

func TestHashFoldEqualsHashRawOfLowercase(t *testing.T) {
	t.Parallel()

	inputs := slices.Grow([]string{
		"", ".", "..", "a", "A", "lizard", "LIZARD", "example.com", "EXAMPLE.com", "ExAmPlE.CoM",
		"Bücher.example", "BÜCHER.EXAMPLE", "İSTANBUL.example", "ǅ.example", "xn--bcher-kva.example",
		"\xff", "A\xffB", "\xc3", "[@\x7f", "`{",
		strings.Repeat("Ab.", longInputLabels),
	}, randomInputs)

	rng := rand.New(rand.NewPCG(1, 2))
	alphabet := []string{"a", "Z", "m", "0", ".", "-", "_", "Ü", "ü", "ß", "İ", "\xff", "é"}

	for range randomInputs {
		var sb strings.Builder

		for range rng.IntN(maxRandomLength) {
			sb.WriteString(alphabet[rng.IntN(len(alphabet))])
		}

		inputs = append(inputs, sb.String())
	}

	for _, in := range inputs {
		if got, want := hashFold(testSeed, in), hashRaw(testSeed, strings.ToLower(in)); got != want {
			t.Errorf("hashFold(%q) = %x, want hashRaw(ToLower) = %x", in, got, want)
		}
	}
}

func TestHashRawIsCaseSensitive(t *testing.T) {
	t.Parallel()

	if hashRaw(testSeed, "lizard") == hashRaw(testSeed, "LIZARD") {
		t.Error("hashRaw must hash the bytes as they are")
	}
}

func TestHashReversedHashesBytesFromLastToFirst(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "a", "lizard", "Example.COM", "bücher.example", "\xff\x00"} {
		reversed := []byte(in)
		slices.Reverse(reversed)

		if got, want := hashReversed(testSeed, in), hashRaw(testSeed, string(reversed)); got != want {
			t.Errorf("hashReversed(%q) = %x, want hashRaw of the reversed bytes = %x", in, got, want)
		}
	}
}

func TestHashDependsOnSeed(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "lizard", "example.com"} {
		if hashFold(1, in) == hashFold(2, in) {
			t.Errorf("hashFold(%q): different seeds must hash the same text differently", in)
		}

		if hashReversed(1, in) == hashReversed(2, in) {
			t.Errorf("hashReversed(%q): different seeds must hash the same text differently", in)
		}
	}
}

func TestMixIsInjectiveOnSample(t *testing.T) {
	t.Parallel()

	inputs := make([]uint64, 0, 3+mixSamples)
	inputs = append(inputs, math.MaxUint64, math.MaxUint64-1, 1<<63)
	for i := range uint64(mixSamples) { // includes 0 and 1
		inputs = append(inputs, i)
	}

	seen := make(map[uint64]uint64, len(inputs))

	for _, in := range inputs {
		out := mix(in)
		if prev, dup := seen[out]; dup {
			t.Fatalf("mix(%#x) and mix(%#x) both give %#x", prev, in, out)
		}

		seen[out] = in
	}
}

// A hashSet indexes its buckets by the top bits of a hash, so mix must spread
// even the most regular input (consecutive integers) over all of them.
func TestMixSpreadsConsecutiveInputsOverTopBits(t *testing.T) {
	t.Parallel()

	hit := make(map[uint64]struct{})

	for i := range uint64(mixSamples) {
		hit[mix(i)>>(hashBits-topBitsPerIndex)] = struct{}{}
	}

	if got, want := len(hit), 1<<topBitsPerIndex; got != want {
		t.Errorf("%d consecutive inputs reached %d of %d top-bit buckets", mixSamples, got, want)
	}
}
