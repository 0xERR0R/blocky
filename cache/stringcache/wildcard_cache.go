package stringcache

import (
	"hash/maphash"
	"math/bits"
	"slices"
	"sort"
	"strings"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/trie"
)

const (
	wildcardFilterWordBits       = 64
	wildcardFilterEntriesPerWord = 8
)

type wildcardCache struct {
	tlds map[string]wildcardBucket
	seed maphash.Seed
	cnt  int
}

// Each TLD shares sorted, concatenated buckets by length, without repeating
// the TLD in each entry. A nil entries map matches the TLD itself.
type wildcardBucket struct {
	entries stringMap
	filter  []uint64
}

func (cache wildcardCache) elementCount() int {
	return cache.cnt
}

func (cache wildcardCache) findMatch(domain string) (string, bool) {
	tld, rest := trie.SplitTLD(domain)
	bucket, ok := cache.tlds[tld]
	if !ok {
		return "", false
	}

	var rule string
	if bucket.entries == nil {
		rule = "*." + tld
	} else {
		base, found := bucket.findBase(rest, cache.seed)
		if !found {
			return "", false
		}

		rule = "*." + base + "." + tld
	}

	logMatch("wildcard_cache", "wildcard block rule", rule, domain)

	return rule, true
}

func (b wildcardBucket) findBase(domain string, seed maphash.Seed) (string, bool) {
	domain = strings.Trim(domain, ".")

	// Search the broadest parent first, preserving the trie's reported rule
	// even when the list also contains children of that parent.
	for i := len(domain) - 1; i >= 0; i-- {
		if i != 0 && domain[i-1] != '.' {
			continue
		}

		if domain[i] == '.' {
			return b.findBaseSkippingEmptyLabels(domain, seed)
		}

		key := domain[i:]
		word, mask := b.filterBits(seed, key)
		if b.filter[word]&mask != mask {
			continue
		}

		width := len(key)
		entries := b.entries[width]

		idx := sort.Search(len(entries)/width, func(j int) bool {
			return entries[j*width:(j+1)*width] >= key
		})
		if idx < len(entries)/width && entries[idx*width:(idx+1)*width] == key {
			return entries[idx*width : (idx+1)*width], true
		}
	}

	return "", false
}

// SplitTLD skipped empty labels in the trie. Preserve that behavior for direct
// cache callers and HTTP queries; only repeated-dot queries need this rewrite.
func (b wildcardBucket) findBaseSkippingEmptyLabels(domain string, seed maphash.Seed) (string, bool) {
	var buf [256]byte
	clean := buf[:0]
	for i := range len(domain) {
		if domain[i] != '.' || i == 0 || domain[i-1] != '.' {
			clean = append(clean, domain[i])
		}
	}

	return b.findBase(string(clean), seed)
}

// filterBits maps key to one filter word and two bits in it, so a probe reads a
// single cache line. The filter only rejects definite misses; binary search
// verifies every hit.
func (b wildcardBucket) filterBits(seed maphash.Seed, key string) (word, mask uint64) {
	hash := maphash.String(seed, key)
	first := hash % wildcardFilterWordBits
	second := (hash / wildcardFilterWordBits) % wildcardFilterWordBits
	// len(b.filter) is a power of two, so the mask selects a valid word.
	word = (hash / (wildcardFilterWordBits * wildcardFilterWordBits)) & (uint64(len(b.filter)) - 1)

	return word, 1<<first | 1<<second
}

type wildcardCacheFactory struct {
	tmp map[string]map[int][]string
	cnt int
}

func newWildcardCacheFactory() cacheFactory {
	return &wildcardCacheFactory{tmp: make(map[string]map[int][]string)}
}

func (r *wildcardCacheFactory) addEntry(entry string) bool {
	globCount := strings.Count(entry, "*")
	if globCount == 0 {
		return false
	}

	if !strings.HasPrefix(entry, "*.") || globCount > 1 {
		log.Log().Warnf("unsupported wildcard '%s': must start with '*.' and contain no other '*'", entry)

		return true // invalid but handled
	}

	r.cnt++
	entry = normalizeWildcard(entry)
	if entry == "" {
		return true
	}

	if strings.Contains(entry, "..") {
		entry = strings.Join(strings.FieldsFunc(entry, func(c rune) bool { return c == '.' }), ".")
	}

	tld, rest := trie.SplitTLD(entry)
	if r.tmp[tld] == nil {
		r.tmp[tld] = make(map[int][]string)
	}

	r.tmp[tld][len(rest)] = append(r.tmp[tld][len(rest)], rest)

	return true
}

func (r *wildcardCacheFactory) count() int {
	return r.cnt
}

func (r *wildcardCacheFactory) create() stringCache {
	if r.cnt == 0 {
		return nil
	}

	cache := wildcardCache{
		tlds: make(map[string]wildcardBucket, len(r.tmp)),
		seed: maphash.MakeSeed(),
		cnt:  r.cnt,
	}

	for tld, lengths := range r.tmp {
		bucket := wildcardBucket{}
		if len(lengths[0]) == 0 {
			bucket.entries = make(stringMap, len(lengths))
			count := 0

			for width, entries := range lengths {
				slices.Sort(entries)
				entries = slices.Compact(entries)
				count += len(entries)
				bucket.entries[width] = strings.Join(entries, "")
				delete(lengths, width)
			}

			// At least eight bits per entry, in a power-of-two number of words.
			bucket.filter = make([]uint64, 1<<bits.Len(uint(count/wildcardFilterEntriesPerWord)))
			for width, entries := range bucket.entries {
				for i := 0; i < len(entries); i += width {
					word, mask := bucket.filterBits(cache.seed, entries[i:i+width])
					bucket.filter[word] |= mask
				}
			}
		}

		cache.tlds[strings.Clone(tld)] = bucket
		delete(r.tmp, tld)
	}

	return cache
}

func normalizeWildcard(domain string) string {
	return strings.Trim(normalizeEntry(strings.TrimLeft(domain, "*")), ".")
}
