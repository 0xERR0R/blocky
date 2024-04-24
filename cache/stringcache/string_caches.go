package stringcache

import (
	"regexp"
	"sort"
	"strings"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/trie"
)

type stringCache interface {
	elementCount() int
	contains(searchString string) bool
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

func (cache stringMap) elementCount() int {
	count := 0

	for k, v := range cache {
		count += len(v) / k
	}

	return count
}

func (cache stringMap) contains(searchString string) bool {
	normalized := normalizeEntry(searchString)
	searchLen := len(normalized)

	if searchLen == 0 {
		return false
	}

	searchBucketLen := len(cache[searchLen]) / searchLen
	idx := sort.Search(searchBucketLen, func(i int) bool {
		return cache[searchLen][i*searchLen:i*searchLen+searchLen] >= normalized
	})

	if idx < searchBucketLen {
		blockRule := cache[searchLen][idx*searchLen : idx*searchLen+searchLen]
		if blockRule == normalized {
			log.PrefixedLog("string_map").Debugf("block rule '%s' matched with '%s'", blockRule, searchString)

			return true
		}
	}

	return false
}

type stringCacheFactory struct {
	// temporary map which holds sorted slice of strings grouped by string length
	tmp map[int][]string
	cnt int
}

func newStringCacheFactory() cacheFactory {
	return &stringCacheFactory{
		tmp: make(map[int][]string),
	}
}

func (s *stringCacheFactory) getBucket(length int) []string {
	if s.tmp[length] == nil {
		s.tmp[length] = make([]string, 0)
	}

	return s.tmp[length]
}

func (s *stringCacheFactory) count() int {
	return s.cnt
}

func (s *stringCacheFactory) insertString(entry string) {
	normalized := normalizeEntry(entry)
	entryLen := len(normalized)
	bucket := s.getBucket(entryLen)
	ix := sort.SearchStrings(bucket, normalized)

	if !(ix < len(bucket) && bucket[ix] == normalized) {
		// extend internal bucket
		bucket = append(s.getBucket(entryLen), "")

		// move elements to make place for the insertion
		copy(bucket[ix+1:], bucket[ix:])

		// insert string at the calculated position
		bucket[ix] = normalized
		s.tmp[entryLen] = bucket
	}
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
		cache[k] = strings.Join(v, "")
	}

	return cache
}

type regexCache []*regexp.Regexp

func (cache regexCache) elementCount() int {
	return len(cache)
}

func (cache regexCache) contains(searchString string) bool {
	for _, regex := range cache {
		if regex.MatchString(searchString) {
			log.PrefixedLog("regex_cache").Debugf("regex '%s' matched with '%s'", regex, searchString)

			return true
		}
	}

	return false
}

type regexCacheFactory struct {
	cache regexCache
}

func (r *regexCacheFactory) addEntry(entry string) bool {
	if !strings.HasPrefix(entry, "/") || !strings.HasSuffix(entry, "/") {
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

type wildcardCache struct {
	trie trie.Trie
	cnt  int
}

func (cache wildcardCache) elementCount() int {
	return cache.cnt
}

func (cache wildcardCache) contains(domain string) bool {
	return cache.trie.HasParentOf(domain)
}

type wildcardCacheFactory struct {
	trie *trie.Trie
	cnt  int
}

func newWildcardCacheFactory() cacheFactory {
	return &wildcardCacheFactory{
		trie: trie.NewTrie(trie.SplitTLD),
	}
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

	entry = normalizeWildcard(entry)

	r.trie.Insert(entry)

	r.cnt++

	return true
}

func (r *wildcardCacheFactory) count() int {
	return r.cnt
}

func (r *wildcardCacheFactory) create() stringCache {
	if r.cnt == 0 {
		return nil
	}

	return wildcardCache{*r.trie, r.cnt}
}

func normalizeWildcard(domain string) string {
	domain = normalizeEntry(domain)
	domain = strings.TrimLeft(domain, "*")
	domain = strings.Trim(domain, ".")
	domain = strings.ToLower(domain)

	return domain
}
