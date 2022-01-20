package stringcache

import (
	"regexp"
	"sort"
	"strings"

	"github.com/0xERR0R/blocky/log"

	"github.com/0xERR0R/blocky/util"
)

type StringCache interface {
	ElementCount() int
	Contains(searchString string) bool
}

type CacheFactory interface {
	AddEntry(entry string)
	Create() StringCache
}

type stringCache map[int]string

func (cache stringCache) ElementCount() int {
	count := 0

	for k, v := range cache {
		count += len(v) / k
	}

	return count
}

func (cache stringCache) Contains(searchString string) bool {
	searchLen := len(searchString)
	if searchLen == 0 {
		return false
	}

	searchBucketLen := len(cache[searchLen]) / searchLen
	idx := sort.Search(searchBucketLen, func(i int) bool {
		return cache[searchLen][i*searchLen:i*searchLen+searchLen] >= searchString
	})

	if idx < searchBucketLen {
		return cache[searchLen][idx*searchLen:idx*searchLen+searchLen] == strings.ToLower(searchString)
	}

	return false
}

type stringCacheFactory struct {
	cache stringCache
	keys  map[string]struct{}
	tmp   map[int]*strings.Builder
}

func newStringCacheFactory() CacheFactory {
	return &stringCacheFactory{
		cache: make(stringCache),
		// temporary map to remove duplicates
		keys: make(map[string]struct{}),
		tmp:  make(map[int]*strings.Builder),
	}
}

func (s *stringCacheFactory) AddEntry(entry string) {
	if _, value := s.keys[entry]; !value {
		s.keys[entry] = struct{}{}
		if s.tmp[len(entry)] == nil {
			s.tmp[len(entry)] = &strings.Builder{}
		}

		s.tmp[len(entry)].WriteString(entry)
	}
}

func (s *stringCacheFactory) Create() StringCache {
	for k, v := range s.tmp {
		chunks := util.Chunks(v.String(), k)
		sort.Strings(chunks)

		s.cache[k] = strings.Join(chunks, "")

		v.Reset()
	}

	return s.cache
}

type regexCache []*regexp.Regexp

func (cache regexCache) ElementCount() int {
	return len(cache)
}

func (cache regexCache) Contains(searchString string) bool {
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

func (r *regexCacheFactory) AddEntry(entry string) {
	compile, err := regexp.Compile(entry)
	if err != nil {
		log.Log().Warnf("invalid regex '%s'", entry)
	} else {
		r.cache = append(r.cache, compile)
	}
}

func (r *regexCacheFactory) Create() StringCache {
	return r.cache
}

func newRegexCacheFactory() CacheFactory {
	return &regexCacheFactory{
		cache: make(regexCache, 0),
	}
}

type chainedCache struct {
	caches []StringCache
}

func (cache chainedCache) ElementCount() int {
	sum := 0
	for _, c := range cache.caches {
		sum += c.ElementCount()
	}

	return sum
}

func (cache chainedCache) Contains(searchString string) bool {
	for _, c := range cache.caches {
		if c.Contains(searchString) {
			return true
		}
	}

	return false
}

type chainedCacheFactory struct {
	stringCacheFactory CacheFactory
	regexCacheFactory  CacheFactory
}

var regexPattern = regexp.MustCompile("^/.*/$")

func (r *chainedCacheFactory) AddEntry(entry string) {
	if regexPattern.MatchString(entry) {
		entry = strings.TrimSpace(strings.Trim(entry, "/"))
		r.regexCacheFactory.AddEntry(entry)
	} else {
		r.stringCacheFactory.AddEntry(entry)
	}
}

func (r *chainedCacheFactory) Create() StringCache {
	return &chainedCache{
		caches: []StringCache{r.stringCacheFactory.Create(), r.regexCacheFactory.Create()},
	}
}

func NewChainedCacheFactory() CacheFactory {
	return &chainedCacheFactory{
		stringCacheFactory: newStringCacheFactory(),
		regexCacheFactory:  newRegexCacheFactory(),
	}
}
