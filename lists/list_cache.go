package lists

//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names
import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/0xERR0R/blocky/cache/stringcache"
	"github.com/sirupsen/logrus"

	"github.com/hako/durafmt"

	"github.com/hashicorp/go-multierror"

	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/log"
)

const (
	defaultProcessingConcurrency = 4
	chanCap                      = 1000
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
	groupCaches map[string]stringcache.StringCache
	lock        sync.RWMutex

	groupToLinks          map[string][]string
	refreshPeriod         time.Duration
	downloader            FileDownloader
	listType              ListCacheType
	processingConcurrency uint
}

// Configuration returns current configuration and stats
func (b *ListCache) Configuration() (result []string) {
	if b.refreshPeriod > 0 {
		result = append(result, fmt.Sprintf("refresh period: %s", durafmt.Parse(b.refreshPeriod)))
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

	b.lock.RLock()
	defer b.lock.RUnlock()

	for group, cache := range b.groupCaches {
		result = append(result, fmt.Sprintf("  %s: %d entries", group, cache.ElementCount()))
		total += cache.ElementCount()
	}

	result = append(result, fmt.Sprintf("  TOTAL: %d entries", total))

	return result
}

// NewListCache creates new list instance
func NewListCache(t ListCacheType, groupToLinks map[string][]string, refreshPeriod time.Duration,
	downloader FileDownloader, processingConcurrency uint, async bool,
) (*ListCache, error) {
	groupCaches := make(map[string]stringcache.StringCache)

	if processingConcurrency == 0 {
		processingConcurrency = defaultProcessingConcurrency
	}

	b := &ListCache{
		groupToLinks:          groupToLinks,
		groupCaches:           groupCaches,
		refreshPeriod:         refreshPeriod,
		downloader:            downloader,
		listType:              t,
		processingConcurrency: processingConcurrency,
	}

	var initError error
	if async {
		initError = nil

		// start list refresh in the background
		go b.Refresh()
	} else {
		initError = b.refresh(true)
	}

	if initError == nil {
		go periodicUpdate(b)
	}

	return b, initError
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
func (b *ListCache) createCacheForGroup(links []string) (stringcache.StringCache, error) {
	var err error

	factory := stringcache.NewChainedCacheFactory()

	fileLinesChan := make(chan string, chanCap)
	errChan := make(chan error, chanCap)

	workerDoneChan := make(chan bool, len(links))

	// guard channel is used to limit the number of concurrent executions of the function
	guard := make(chan struct{}, b.processingConcurrency)

	processingLinkJobs := len(links)

	// loop over links (http/local) or inline definitions
	// start a new goroutine for each link, but limit to max. number (see processingConcurrency)
	for _, link := range links {
		go func(link string) {
			// thy to write in this channel -> this will block if max amount of goroutines are being executed
			guard <- struct{}{}

			defer func() {
				// remove from guard channel to allow other blocked goroutines to continue
				<-guard
				workerDoneChan <- true
			}()
			b.processFile(link, fileLinesChan, errChan)
		}(link)
	}

Loop:
	for {
		select {
		case line := <-fileLinesChan:
			factory.AddEntry(line)
		case e := <-errChan:
			var transientErr *TransientError

			if errors.As(e, &transientErr) {
				return nil, e
			}
			err = multierror.Append(err, e)
		case <-workerDoneChan:
			processingLinkJobs--

		default:
			if processingLinkJobs == 0 {
				break Loop
			}
		}
	}

	return factory.Create(), err
}

// Match matches passed domain name against cached list entries
func (b *ListCache) Match(domain string, groupsToCheck []string) (found bool, group string) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	for _, g := range groupsToCheck {
		if c, ok := b.groupCaches[g]; ok && c.Contains(domain) {
			return true, g
		}
	}

	return false, ""
}

// Refresh triggers the refresh of a list
func (b *ListCache) Refresh() {
	_ = b.refresh(false)
}

func (b *ListCache) refresh(init bool) error {
	var err error

	for group, links := range b.groupToLinks {
		cacheForGroup, e := b.createCacheForGroup(links)
		if e != nil {
			err = multierror.Append(err, multierror.Prefix(e, fmt.Sprintf("can't create cache group '%s':", group)))
		}

		if cacheForGroup != nil {
			b.lock.Lock()
			b.groupCaches[group] = cacheForGroup
			b.lock.Unlock()
		} else {
			if init {
				msg := "Populating group cache failed for group " + group
				logger().Warn(msg)
			} else {
				logger().Warn("Populating of group cache failed, leaving items from last successful download in cache")
			}
		}

		if cacheForGroup != nil {
			evt.Bus().Publish(evt.BlockingCacheGroupChanged, b.listType, group, cacheForGroup.ElementCount())

			logger().WithFields(logrus.Fields{
				"group":       group,
				"total_count": cacheForGroup.ElementCount(),
			}).Info("group import finished")
		}
	}

	return err
}

func readFile(file string) (io.ReadCloser, error) {
	logger().WithField("file", file).Info("starting processing of file")
	file = strings.TrimPrefix(file, "file://")

	return os.Open(file)
}

// downloads file (or reads local file) and writes each line in the file to the result channel
func (b *ListCache) processFile(link string, resultCh chan<- string, errCh chan<- error) {
	var r io.ReadCloser

	var err error

	r, err = b.getLinkReader(link)

	if err != nil {
		logger().Warn("error during file processing: ", err)
		errCh <- err

		return
	}
	defer r.Close()

	var count int

	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// skip comments
		if line := processLine(line); line != "" {
			resultCh <- line

			count++
		}
	}

	if err := scanner.Err(); err != nil {
		// don't propagate error here. If some lines are not parsable (e.g. too long), it is ok
		logger().Warn("can't parse file: ", err)
	} else {
		logger().WithFields(logrus.Fields{
			"source": link,
			"count":  count,
		}).Info("file imported")
	}
}

func (b *ListCache) getLinkReader(link string) (r io.ReadCloser, err error) {
	switch {
	// link contains a line break -> this is inline list definition in YAML (with literal style Block Scalar)
	case strings.ContainsAny(link, "\n"):
		r = io.NopCloser(strings.NewReader(link))
	// link is http(s) -> download it
	case strings.HasPrefix(link, "http"):
		r, err = b.downloader.DownloadFile(link)
	// probably path to a local file
	default:
		r, err = readFile(link)
	}

	return
}

// return only first column (see hosts format)
func processLine(line string) string {
	if strings.HasPrefix(line, "#") {
		return ""
	}

	if parts := strings.Fields(line); len(parts) > 0 {
		host := parts[len(parts)-1]

		ip := net.ParseIP(host)
		if ip != nil {
			return ip.String()
		}

		return strings.TrimSpace(strings.ToLower(host))
	}

	return ""
}
