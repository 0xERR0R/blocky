package stringcache

import (
	"strings"
	"unicode/utf8"

	"github.com/0xERR0R/blocky/log"
)

// wildcardCache matches a domain against "*.suffix" rules, stored as hashes of
// the byte-reversed suffix (see hashReversed). accepted is the number of accepted
// entries, including duplicates and entries that match nothing.
type wildcardCache struct {
	seed     uint64
	set      hashSet
	accepted int
}

func (c wildcardCache) elementCount() int {
	return c.accepted
}

func (c wildcardCache) findMatch(query string) (string, bool) {
	domain := query

	start, found, nonASCII := c.walk(domain)
	if nonASCII {
		// Unicode case folding can't be done byte by byte: retry on the lowered text.
		domain = strings.ToLower(domain)
		start, found, _ = c.walk(domain)
	}

	if !found {
		return "", false
	}

	rule := "*." + strings.ToLower(collapseDots(strings.TrimRight(domain[start:], ".")))
	logMatch("wildcard_cache", "wildcard block rule", rule, query)

	return rule, true
}

// walk hashes domain from its end towards its start, ASCII case-insensitively
// and ignoring empty labels, as if the dots were trimmed and collapsed first.
// It probes the hash of every label-boundary suffix, shortest first, so the
// broadest matching parent wins. start is the offset in domain of the first
// matching suffix; nonASCII reports that domain has bytes that can't be folded.
func (c wildcardCache) walk(domain string) (start int, found, nonASCII bool) {
	var (
		h        = fnvBasis(c.seed)
		labelLen int
		highBits byte
	)

	for i := len(domain) - 1; i >= 0; i-- {
		b := domain[i]

		if b != '.' {
			highBits |= b
			h = fnvStep(h, lowerASCII(b))
			labelLen++

			continue
		}

		if labelLen == 0 {
			continue // empty label: leading, trailing or repeated dot
		}

		// The label ending right after this dot is complete.
		if c.set.contains(mix(h)) {
			return i + 1, true, highBits >= utf8.RuneSelf
		}

		h = fnvStep(h, b)
		labelLen = 0
	}

	return 0, labelLen > 0 && c.set.contains(mix(h)), highBits >= utf8.RuneSelf
}

type wildcardCacheFactory struct {
	entries  hashedEntries
	accepted int
}

func newWildcardCacheFactory() cacheFactory {
	return &wildcardCacheFactory{entries: newHashedEntries()}
}

func (f *wildcardCacheFactory) addEntry(entry string) bool {
	globCount := strings.Count(entry, "*")
	if globCount == 0 {
		return false
	}

	if !strings.HasPrefix(entry, "*.") || globCount > 1 {
		log.Log().Warnf("unsupported wildcard '%s': must start with '*.' and contain no other '*'", entry)

		return true // invalid but handled
	}

	f.accepted++

	domain := collapseDots(normalizeWildcard(entry))
	if domain == "" {
		log.Log().Warnf("empty wildcard '%s': it has no domain and matches nothing", entry)

		return true // invalid but handled
	}

	f.entries.add(hashReversed(f.entries.seed, domain))

	return true
}

func (f *wildcardCacheFactory) count() int {
	return f.accepted
}

func (f *wildcardCacheFactory) create() stringCache {
	if f.accepted == 0 {
		return nil
	}

	return wildcardCache{seed: f.entries.seed, set: f.entries.build(), accepted: f.accepted}
}

// normalizeWildcard turns a "*.example.com" entry into its lowercase suffix "example.com".
func normalizeWildcard(domain string) string {
	return strings.Trim(strings.ToLower(strings.TrimLeft(domain, "*")), ".")
}

// collapseDots replaces runs of dots by a single dot.
func collapseDots(domain string) string {
	if !strings.Contains(domain, "..") {
		return domain
	}

	return strings.Join(strings.FieldsFunc(domain, func(c rune) bool { return c == '.' }), ".")
}
