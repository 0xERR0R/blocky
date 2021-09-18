package lists

import (
	"regexp"
	"sort"
	"strings"

	"github.com/0xERR0R/blocky/log"

	"github.com/0xERR0R/blocky/util"
)

type cache interface {
	elementCount() int
	contains(searchString string) bool
}

type cacheFactory interface {
	addEntry(entry string)
	create() cache
}

type stringCache map[int]string

func (cache stringCache) elementCount() int {
	count := 0

	for k, v := range cache {
		count += len(v) / k
	}

	return count
}

func (cache stringCache) contains(searchString string) bool {
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

func newStringCacheFactory() cacheFactory {
	return &stringCacheFactory{
		cache: make(stringCache),
		// temporary map to remove duplicates
		keys: make(map[string]struct{}),
		tmp:  make(map[int]*strings.Builder),
	}
}

func (s *stringCacheFactory) addEntry(entry string) {
	if _, value := s.keys[entry]; !value {
		s.keys[entry] = struct{}{}
		if s.tmp[len(entry)] == nil {
			s.tmp[len(entry)] = &strings.Builder{}
		}

		s.tmp[len(entry)].WriteString(entry)
	}
}

func (s *stringCacheFactory) create() cache {
	for k, v := range s.tmp {
		chunks := util.Chunks(v.String(), k)
		sort.Strings(chunks)

		s.cache[k] = strings.Join(chunks, "")

		v.Reset()
	}

	return s.cache
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
	compile, err := regexp.Compile(entry)
	if err != nil {
		log.Log().Warnf("invalid regex '%s'", entry)
	} else {
		r.cache = append(r.cache, compile)
	}
}

func (r *regexCacheFactory) create() cache {
	return r.cache
}

func newRegexCacheFactory() cacheFactory {
	return &regexCacheFactory{
		cache: make(regexCache, 0),
	}
}

type chainedCache struct {
	caches []cache
}

func (cache chainedCache) elementCount() int {
	sum := 0
	for _, c := range cache.caches {
		sum += c.elementCount()
	}

	return sum
}

func (cache chainedCache) contains(searchString string) bool {
	for _, c := range cache.caches {
		if c.contains(searchString) {
			return true
		}
	}

	return false
}

type chainedCacheFactory struct {
	stringCacheFactory cacheFactory
	regexCacheFactory  cacheFactory
}

var regexPattern = regexp.MustCompile("^/.*/$")

func (r *chainedCacheFactory) addEntry(entry string) {
	if regexPattern.MatchString(entry) {
		entry = strings.TrimSpace(strings.Trim(entry, "/"))
		r.regexCacheFactory.addEntry(entry)
	} else {
		r.stringCacheFactory.addEntry(entry)
	}
}

func (r *chainedCacheFactory) create() cache {
	return &chainedCache{
		caches: []cache{r.stringCacheFactory.create(), r.regexCacheFactory.create()},
	}
}

func newChainedCacheFactory() cacheFactory {
	return &chainedCacheFactory{
		stringCacheFactory: newStringCacheFactory(),
		regexCacheFactory:  newRegexCacheFactory(),
	}
}
