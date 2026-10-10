package stringcache

import (
	"regexp"
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

// logMatch runs on every hit, so it skips the logrus entry and argument
// allocations unless debug logging is on.
func logMatch(prefix, kind, rule, searchString string) {
	if log.Log().IsLevelEnabled(logrus.DebugLevel) {
		log.PrefixedLog(prefix).Debugf("%s '%s' matched with '%s'", kind, rule, searchString)
	}
}

// hashCache matches exact, case-insensitive strings. It stores only their
// hashes; the matched rule is the lowercased search string.
type hashCache struct {
	seed uint64
	set  hashSet
}

func (c hashCache) elementCount() int {
	return c.set.len()
}

func (c hashCache) findMatch(searchString string) (string, bool) {
	if searchString == "" || !c.set.contains(hashFold(c.seed, searchString)) {
		return "", false
	}

	rule := strings.ToLower(searchString)
	logMatch("string_map", "block rule", rule, searchString)

	return rule, true
}

type stringCacheFactory struct {
	entries  hashedEntries
	accepted int
}

func newStringCacheFactory() cacheFactory {
	return &stringCacheFactory{entries: newHashedEntries()}
}

// count returns the number of accepted entries, including duplicates.
func (f *stringCacheFactory) count() int {
	return f.accepted
}

func (f *stringCacheFactory) addEntry(entry string) bool {
	if len(entry) == 0 {
		return true // invalid but handled
	}

	f.entries.add(hashFold(f.entries.seed, entry))
	f.accepted++

	return true
}

func (f *stringCacheFactory) create() stringCache {
	if f.accepted == 0 {
		return nil
	}

	return hashCache{seed: f.entries.seed, set: f.entries.build()}
}

type regexCache []*regexp.Regexp

func (c regexCache) elementCount() int {
	return len(c)
}

func (c regexCache) findMatch(searchString string) (string, bool) {
	for _, regex := range c {
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

func (f *regexCacheFactory) addEntry(entry string) bool {
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

	f.cache = append(f.cache, compile)

	return true
}

func (f *regexCacheFactory) count() int {
	return len(f.cache)
}

func (f *regexCacheFactory) create() stringCache {
	if len(f.cache) == 0 {
		return nil
	}

	return f.cache
}

func newRegexCacheFactory() cacheFactory {
	return &regexCacheFactory{
		cache: make(regexCache, 0),
	}
}
