package lists

//go:generate go-enum -f=$GOFILE --marshal --names
import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"
)

// ListCacheType represents the type of cached list ENUM(
// blacklist // is a list with blocked domains
// whitelist // is a list with whitelisted domains / IPs
// )
type ListCacheType int

// Matcher checks if a domain is in a list
type Matcher interface {
	// Match matches passed domain name against cached list entries
	Match(domain string, groupsToCheck []string) (found bool, group string)

	// Configuration returns current configuration and stats
	Configuration() []string
}

// ListCache generic cache of strings divided in groups
type ListCache struct {
	groupCaches map[string]cache
	lock        sync.RWMutex

	groupToLinks    map[string][]string
	refreshPeriod   time.Duration
	downloadTimeout time.Duration
	listType        ListCacheType
}

// Configuration returns current configuration and stats
func (b *ListCache) Configuration() (result []string) {
	if b.refreshPeriod > 0 {
		result = append(result, fmt.Sprintf("refresh period: %s", b.refreshPeriod))
	} else {
		result = append(result, "refresh: disabled")
	}

	result = append(result, "group links:")
	for group, links := range b.groupToLinks {
		result = append(result, fmt.Sprintf("  %s:", group))

		for _, link := range links {
			if strings.Contains(link, "\n") {
				link = "[INLINE DEFINITION]"
			}

			result = append(result, fmt.Sprintf("   - %s", link))
		}
	}

	result = append(result, "group caches:")

	var total int

	for group, cache := range b.groupCaches {
		result = append(result, fmt.Sprintf("  %s: %d entries", group, cache.elementCount()))
		total += cache.elementCount()
	}

	result = append(result, fmt.Sprintf("  TOTAL: %d entries", total))

	return result
}

// NewListCache creates new list instance
func NewListCache(t ListCacheType, groupToLinks map[string][]string, refreshPeriod time.Duration,
	downloadTimeout time.Duration) *ListCache {
	groupCaches := make(map[string]cache)

	b := &ListCache{
		groupToLinks:    groupToLinks,
		groupCaches:     groupCaches,
		refreshPeriod:   refreshPeriod,
		downloadTimeout: downloadTimeout,
		listType:        t,
	}
	b.Refresh()

	go periodicUpdate(b)

	return b
}

// periodicUpdate triggers periodical refresh (and download) of list entries
func periodicUpdate(cache *ListCache) {
	if cache.refreshPeriod > 0 {
		ticker := time.NewTicker(cache.refreshPeriod)
		defer ticker.Stop()

		for {
			<-ticker.C
			cache.Refresh()
		}
	}
}

func logger() *logrus.Entry {
	return log.PrefixedLog("list_cache")
}

// downloads and reads files with domain names and creates cache for them
func (b *ListCache) createCacheForGroup(links []string) cache {
	var wg sync.WaitGroup

	c := make(chan []string, len(links))

	// loop over links (http/local) or inline definitions
	for _, link := range links {
		wg.Add(1)

		go b.processFile(link, c, &wg)
	}

	wg.Wait()

	factory := newChainedCacheFactory()

Loop:
	for {
		select {
		case res := <-c:
			if res == nil {
				return nil
			}
			for _, entry := range res {
				factory.addEntry(entry)
			}
		default:
			close(c)
			break Loop
		}
	}

	return factory.create()
}

// Match matches passed domain name against cached list entries
func (b *ListCache) Match(domain string, groupsToCheck []string) (found bool, group string) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	for _, g := range groupsToCheck {
		if c, ok := b.groupCaches[g]; ok && c.contains(domain) {
			return true, g
		}
	}

	return false, ""
}

// Refresh triggers the refresh of a list
func (b *ListCache) Refresh() {
	for group, links := range b.groupToLinks {
		cacheForGroup := b.createCacheForGroup(links)

		if cacheForGroup != nil {
			b.lock.Lock()
			b.groupCaches[group] = cacheForGroup
			b.lock.Unlock()
		} else {
			logger().Warn("Populating of group cache failed, leaving items from last successful download in cache")
		}

		evt.Bus().Publish(evt.BlockingCacheGroupChanged, b.listType, group, b.groupCaches[group].elementCount())

		logger().WithFields(logrus.Fields{
			"group":       group,
			"total_count": b.groupCaches[group].elementCount(),
		}).Info("group import finished")
	}
}

func (b *ListCache) downloadFile(link string) (io.ReadCloser, error) {
	client := http.Client{
		Timeout: b.downloadTimeout,
	}

	var resp *http.Response

	var err error

	logger().WithField("link", link).Info("starting download")

	attempt := 1

	for attempt <= 3 {
		//nolint:bodyclose
		if resp, err = client.Get(link); err == nil {
			if resp.StatusCode == http.StatusOK {
				return resp.Body, nil
			}

			_ = resp.Body.Close()

			return nil, fmt.Errorf("couldn't download url '%s', got status code %d", link, resp.StatusCode)
		}

		var netErr net.Error
		if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
			logger().WithField("link", link).WithField("attempt",
				attempt).Warnf("Temporary network error / Timeout occurred, retrying... %s", netErr)
			time.Sleep(time.Second)
			attempt++
		} else {
			return nil, err
		}
	}

	return nil, err
}

func readFile(file string) (io.ReadCloser, error) {
	logger().WithField("file", file).Info("starting processing of file")
	file = strings.TrimPrefix(file, "file://")

	return os.Open(file)
}

// downloads file (or reads local file) and writes file content as string array in the channel
func (b *ListCache) processFile(link string, ch chan<- []string, wg *sync.WaitGroup) {
	defer wg.Done()

	result := make([]string, 0)

	var r io.ReadCloser

	var err error

	switch {
	// link contains a line break -> this is inline list definition in YAML (with literal style Block Scalar)
	case strings.ContainsAny(link, "\n"):
		r = io.NopCloser(strings.NewReader(link))
	// link is http(s) -> download it
	case strings.HasPrefix(link, "http"):
		r, err = b.downloadFile(link)
	// probably path to a local file
	default:
		r, err = readFile(link)
	}

	if err != nil {
		logger().Warn("error during file processing: ", err)

		var netErr net.Error
		if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
			// put nil to indicate the temporary error
			ch <- nil
			return
		}
		ch <- []string{}

		return
	}
	defer r.Close()

	var count int

	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// skip comments
		if line := processLine(line); line != "" {
			result = append(result, line)

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
	if strings.HasPrefix(line, "#") {
		return ""
	}

	parts := strings.Fields(line)

	if len(parts) > 0 {
		host := parts[len(parts)-1]

		ip := net.ParseIP(host)
		if ip != nil {
			return ip.String()
		}

		return strings.TrimSpace(strings.ToLower(host))
	}

	return ""
}
