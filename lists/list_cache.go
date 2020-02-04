package lists

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	timeout              = 30 * time.Second
	defaultRefreshPeriod = 4 * time.Hour
)

type Matcher interface {
	// matches passed domain name against cached list entries
	Match(domain string, groupsToCheck []string) (found bool, group string)

	// returns current configuration and stats
	Configuration() []string
}

type ListCache struct {
	groupCaches map[string][]string
	lock        sync.RWMutex

	groupToLinks  map[string][]string
	refreshPeriod time.Duration
}

func (b *ListCache) Configuration() (result []string) {
	if b.refreshPeriod > 0 {
		result = append(result, fmt.Sprintf("refresh period: %d minutes", b.refreshPeriod/time.Minute))
	} else {
		result = append(result, "refresh: disabled")
	}

	result = append(result, "group links:")
	for group, links := range b.groupToLinks {
		result = append(result, fmt.Sprintf("  %s:", group))
		for _, link := range links {
			result = append(result, fmt.Sprintf("   - %s", link))
		}
	}

	result = append(result, "group caches:")

	var total int

	for group, cache := range b.groupCaches {
		result = append(result, fmt.Sprintf("  %s: %d entries", group, len(cache)))
		total += len(cache)
	}

	result = append(result, fmt.Sprintf("  TOTAL: %d entries", total))

	return
}

// removes duplicates
func unique(in []string) []string {
	keys := make(map[string]bool)

	var list []string

	for _, entry := range in {
		if _, value := keys[entry]; !value {
			keys[entry] = true

			list = append(list, entry)
		}
	}

	return list
}

func NewListCache(groupToLinks map[string][]string, refreshPeriod int) *ListCache {
	groupCaches := make(map[string][]string)

	p := time.Duration(refreshPeriod) * time.Minute
	if refreshPeriod == 0 {
		p = defaultRefreshPeriod
	}

	b := &ListCache{
		groupToLinks:  groupToLinks,
		groupCaches:   groupCaches,
		refreshPeriod: p,
	}
	b.refresh()

	go periodicUpdate(b)

	return b
}

// triggers periodical refresh (and download) of list entries
func periodicUpdate(cache *ListCache) {
	if cache.refreshPeriod > 0 {
		ticker := time.NewTicker(cache.refreshPeriod)
		defer ticker.Stop()

		for {
			<-ticker.C
			cache.refresh()
		}
	}
}

func logger() *logrus.Entry {
	return logrus.WithField("prefix", "list_cache")
}

// downloads and reads files with domain names and creates cache for them
func createCacheForGroup(links []string) []string {
	cache := make([]string, 0)

	var wg sync.WaitGroup

	c := make(chan []string, len(links))

	for _, link := range links {
		wg.Add(1)

		go processFile(link, c, &wg)
	}

	wg.Wait()

Loop:
	for {
		select {
		case res := <-c:
			cache = append(cache, res...)
		default:
			close(c)
			break Loop
		}
	}

	cache = unique(cache)
	sort.Strings(cache)

	return cache
}

func (b *ListCache) Match(domain string, groupsToCheck []string) (found bool, group string) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	for _, g := range groupsToCheck {
		if contains(domain, b.groupCaches[g]) {
			return true, g
		}
	}

	return false, ""
}

func contains(domain string, cache []string) bool {
	idx := sort.SearchStrings(cache, domain)
	if idx < len(cache) {
		return cache[idx] == strings.ToLower(domain)
	}

	return false
}

func (b *ListCache) refresh() {
	b.lock.Lock()
	defer b.lock.Unlock()

	for group, links := range b.groupToLinks {
		b.groupCaches[group] = createCacheForGroup(links)

		logger().WithFields(logrus.Fields{
			"group":       group,
			"total_count": len(b.groupCaches[group]),
		}).Info("group import finished")
	}
}

func downloadFile(link string) (io.ReadCloser, error) {
	client := http.Client{
		Timeout: timeout,
	}

	logger().WithField("link", link).Info("starting download")

	//nolint:bodyclose
	resp, err := client.Get(link)

	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}

func readFile(file string) (io.ReadCloser, error) {
	logger().WithField("file", file).Info("starting processing of file")
	file = strings.TrimPrefix(file, "file://")

	return os.Open(file)
}

// downloads file (or reads local file) and writes file content as string array in the channel
func processFile(link string, ch chan<- []string, wg *sync.WaitGroup) {
	defer wg.Done()

	result := make([]string, 0)

	var r io.ReadCloser

	var err error

	if strings.HasPrefix(link, "http") {
		r, err = downloadFile(link)
	} else {
		r, err = readFile(link)
	}

	if err != nil {
		logger().Warn("error during file processing: ", err)
		return
	}
	defer r.Close()

	var count int

	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		// skip comments
		if !strings.HasPrefix(line, "#") {
			result = append(result, processLine(line))
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		logger().Warn("can't parse file: ", err)
	} else {
		logger().WithFields(logrus.Fields{
			"source": link,
			"count":  count,
		}).Info("file imported")
	}
	ch <- result
}

// return only first column (see hosts format)
func processLine(line string) string {
	parts := strings.Fields(line)
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}

	return ""
}
