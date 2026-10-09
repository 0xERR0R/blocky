package stringcache

import (
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/0xERR0R/blocky/log"
)

type stringCache interface {
	elementCount() int
	// findMatch reports whether the cache matches searchString and, if so,
	// returns the rule that matched. rule is empty when ok is false.
	findMatch(searchString string) (rule string, ok bool)
}

type cacheFactory interface {
	addEntry(entry string) bool
	create() stringCache
	count() int
}

type stringMap map[int]string

func normalizeEntry(entry string) string {
	return strings.ToLower(entry)
}

// logMatch runs on every hit, so it skips the logrus entry and argument
// allocations unless debug logging is on.
func logMatch(prefix, kind, rule, searchString string) {
	if log.Log().IsLevelEnabled(logrus.DebugLevel) {
		log.PrefixedLog(prefix).Debugf("%s '%s' matched with '%s'", kind, rule, searchString)
	}
}

func (cache stringMap) elementCount() int {
	count := 0

	for k, v := range cache {
		count += len(v) / k
	}

	return count
}

func (cache stringMap) findMatch(searchString string) (string, bool) {
	normalized := normalizeEntry(searchString)
	searchLen := len(normalized)

	if searchLen == 0 {
		return "", false
	}

	bucket := cache[searchLen]
	searchBucketLen := len(bucket) / searchLen
	idx := sort.Search(searchBucketLen, func(i int) bool {
		return bucket[i*searchLen:i*searchLen+searchLen] >= normalized
	})

	if idx < searchBucketLen {
		blockRule := bucket[idx*searchLen : idx*searchLen+searchLen]
		if blockRule == normalized {
			logMatch("string_map", "block rule", blockRule, searchString)

			return blockRule, true
		}
	}

	return "", false
}

type stringCacheFactory struct {
	// temporary map which holds slices of entries grouped by string length.
	// Entries are appended as they arrive; each bucket is sorted and
	// deduplicated once, when the cache is created.
	tmp map[int][]string
	cnt int
}

func newStringCacheFactory() cacheFactory {
	return &stringCacheFactory{
		tmp: make(map[int][]string),
	}
}

func (s *stringCacheFactory) count() int {
	return s.cnt
}

func (s *stringCacheFactory) insertString(entry string) {
	normalized := normalizeEntry(entry)
	entryLen := len(normalized)

	// Append and defer sorting/deduplication to create(): inserting in sorted
	// order here would shift the whole bucket on every entry, making cache
	// construction O(n^2) for a list of n entries.
	s.tmp[entryLen] = append(s.tmp[entryLen], normalized)
}

func (s *stringCacheFactory) addEntry(entry string) bool {
	if len(entry) == 0 {
		return true // invalid but handled
	}

	s.cnt++
	s.insertString(entry)

	return true
}

func (s *stringCacheFactory) create() stringCache {
	if len(s.tmp) == 0 {
		return nil
	}

	cache := make(stringMap, len(s.tmp))

	for k, v := range s.tmp {
		// contains() binary-searches the concatenated bucket, so it must be
		// sorted; duplicates are dropped to keep elementCount() and memory use
		// equivalent to inserting one entry at a time.
		slices.Sort(v)
		v = slices.Compact(v)
		cache[k] = strings.Join(v, "")
	}

	return cache
}

type regexCache []*regexp.Regexp

func (cache regexCache) elementCount() int {
	return len(cache)
}

func (cache regexCache) findMatch(searchString string) (string, bool) {
	for _, regex := range cache {
		if regex.MatchString(searchString) {
			logMatch("regex_cache", "regex", regex.String(), searchString)

			// re-wrap in the '/.../' delimiters that addEntry strips on insertion
			// so the reported rule matches the entry as configured by the user.
			return "/" + regex.String() + "/", true
		}
	}

	return "", false
}

type regexCacheFactory struct {
	cache regexCache
}

func (r *regexCacheFactory) addEntry(entry string) bool {
	// A regex entry is delimited by a leading and a trailing slash (/regex/), so
	// it needs at least those two characters. Without the length guard a lone
	// "/" satisfies both HasPrefix and HasSuffix and then panics below, where the
	// delimiters are stripped (entry[1:len-1] would be "/"[1:0]).
	if len(entry) < 2 || !strings.HasPrefix(entry, "/") || !strings.HasSuffix(entry, "/") {
		return false
	}

	// Trim slashes
	entry = strings.TrimSpace(entry[1 : len(entry)-1])

	compile, err := regexp.Compile(entry)
	if err != nil {
		log.Log().Warnf("invalid regex '%s'", entry)

		return true // invalid but handled
	}

	r.cache = append(r.cache, compile)

	return true
}

func (r *regexCacheFactory) count() int {
	return len(r.cache)
}

func (r *regexCacheFactory) create() stringCache {
	if len(r.cache) == 0 {
		return nil
	}

	return r.cache
}

func newRegexCacheFactory() cacheFactory {
	return &regexCacheFactory{
		cache: make(regexCache, 0),
	}
}
