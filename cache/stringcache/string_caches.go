package stringcache

import (
	"regexp"
	"sort"
	"strings"

	"github.com/0xERR0R/blocky/log"
)

type stringCache interface {
	elementCount() int
	contains(searchString string) bool
}

type cacheFactory interface {
	addEntry(entry string)
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
		return cache[searchLen][idx*searchLen:idx*searchLen+searchLen] == strings.ToLower(normalized)
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
		// extent internal bucket
		bucket = append(s.getBucket(entryLen), "")

		// move elements to make place for the insertion
		copy(bucket[ix+1:], bucket[ix:])

		// insert string at the calculated position
		bucket[ix] = normalized
		s.tmp[entryLen] = bucket
	}
}

func (s *stringCacheFactory) addEntry(entry string) {
	// skip empty strings and regex
	if len(entry) > 0 && !isRegex(entry) {
		s.cnt++
		s.insertString(entry)
	}
}

func (s *stringCacheFactory) create() stringCache {
	cache := make(stringMap, len(s.tmp))
	for k, v := range s.tmp {
		cache[k] = strings.Join(v, "")
	}

	s.tmp = nil

	return cache
}

func isRegex(s string) bool {
	return strings.HasPrefix(s, "/") && strings.HasSuffix(s, "/")
}

type regexCache []*regexp.Regexp

func (cache regexCache) elementCount() int {
	return len(cache)
}

func (cache regexCache) contains(searchString string) bool {
	for _, regex := range cache {
		if regex.MatchString(searchString) {
			log.PrefixedLog("regexCache").Debugf("regex '%s' matched with '%s'", regex, searchString)

			return true
		}
	}

	return false
}

type regexCacheFactory struct {
	cache regexCache
}

func (r *regexCacheFactory) addEntry(entry string) {
	if isRegex(entry) {
		entry = strings.TrimSpace(entry[1 : len(entry)-1])
		compile, err := regexp.Compile(entry)

		if err != nil {
			log.Log().Warnf("invalid regex '%s'", entry)
		} else {
			r.cache = append(r.cache, compile)
		}
	}
}

func (r *regexCacheFactory) count() int {
	return len(r.cache)
}

func (r *regexCacheFactory) create() stringCache {
	return r.cache
}

func newRegexCacheFactory() cacheFactory {
	return &regexCacheFactory{
		cache: make(regexCache, 0),
	}
}
