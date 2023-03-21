package lists

//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names
import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/sirupsen/logrus"

	"github.com/0xERR0R/blocky/cache/stringcache"
	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/lists/parsers"
	"github.com/0xERR0R/blocky/log"
)

const (
	defaultProcessingConcurrency = 4
	chanCap                      = 1000
	maxErrorsPerFile             = 5
)

// ListCacheType represents the type of cached list ENUM(
// blacklist // is a list with blocked domains
// whitelist // is a list with whitelisted domains / IPs
// )
type ListCacheType int

// Matcher checks if a domain is in a list
type Matcher interface {
	// Match matches passed domain name against cached list entries
	Match(domain string, groupsToCheck []string) (groups []string)
}

// ListCache generic cache of strings divided in groups
type ListCache struct {
	groupedCache stringcache.GroupedStringCache

	groupToLinks          map[string][]string
	refreshPeriod         time.Duration
	downloader            FileDownloader
	listType              ListCacheType
	processingConcurrency uint
}

// LogConfig implements `config.Configurable`.
func (b *ListCache) LogConfig(logger *logrus.Entry) {
	var total int

	for group := range b.groupToLinks {
		count := b.groupedCache.ElementCount(group)
		logger.Infof("%s: %d entries", group, count)
		total += count
	}

	logger.Infof("TOTAL: %d entries", total)
}

// NewListCache creates new list instance
func NewListCache(t ListCacheType, groupToLinks map[string][]string, refreshPeriod time.Duration,
	downloader FileDownloader, processingConcurrency uint, async bool,
) (*ListCache, error) {
	if processingConcurrency == 0 {
		processingConcurrency = defaultProcessingConcurrency
	}

	b := &ListCache{
		groupedCache: stringcache.NewChainedGroupedCache(
			stringcache.NewInMemoryGroupedStringCache(),
			stringcache.NewInMemoryGroupedRegexCache(),
		),
		groupToLinks:          groupToLinks,
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
//
//nolint:funlen // will refactor in a later commit
func (b *ListCache) createCacheForGroup(group string, links []string) (created bool, err error) {
	groupFactory := b.groupedCache.Refresh(group)

	fileLinesChan := make(chan string, chanCap)
	errChan := make(chan error, chanCap)

	workerDoneChan := make(chan bool, len(links))

	// guard channel is used to limit the number of concurrent executions of the function
	guard := make(chan struct{}, b.processingConcurrency)

	processingLinkJobs := len(links)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// loop over links (http/local) or inline definitions
	// start a new goroutine for each link, but limit to max. number (see processingConcurrency)
	for idx, link := range links {
		go func(idx int, link string) {
			// try to write in this channel -> this will block if max amount of goroutines are being executed
			guard <- struct{}{}

			defer func() {
				// remove from guard channel to allow other blocked goroutines to continue
				<-guard
				workerDoneChan <- true
			}()

			name := linkName(idx, link)

			err := b.parseFile(ctx, name, link, fileLinesChan)
			if err != nil {
				errChan <- err
			}
		}(idx, link)
	}

Loop:
	for {
		select {
		case line := <-fileLinesChan:
			groupFactory.AddEntry(line)
		case e := <-errChan:
			var transientErr *TransientError

			if errors.As(e, &transientErr) {
				return false, e
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

	if groupFactory.Count() == 0 && err != nil {
		return false, err
	}

	groupFactory.Finish()

	return true, err
}

// Match matches passed domain name against cached list entries
func (b *ListCache) Match(domain string, groupsToCheck []string) (groups []string) {
	return b.groupedCache.Contains(domain, groupsToCheck)
}

// Refresh triggers the refresh of a list
func (b *ListCache) Refresh() {
	_ = b.refresh(false)
}

func (b *ListCache) refresh(isInit bool) error {
	var err error

	for group, links := range b.groupToLinks {
		created, e := b.createCacheForGroup(group, links)
		if e != nil {
			err = multierror.Append(err, multierror.Prefix(e, fmt.Sprintf("can't create cache group '%s':", group)))
		}

		count := b.groupedCache.ElementCount(group)

		if !created {
			logger := logger().WithFields(logrus.Fields{
				"group":       group,
				"total_count": count,
			})

			if count == 0 || isInit {
				logger.Warn("Populating of group cache failed, cache will be empty until refresh succeeds")
			} else {
				logger.Warn("Populating of group cache failed, using existing cache, if any")
			}

			continue
		}

		evt.Bus().Publish(evt.BlockingCacheGroupChanged, b.listType, group, count)

		logger().WithFields(logrus.Fields{
			"group":       group,
			"total_count": count,
		}).Info("group import finished")
	}

	return err
}

func readFile(file string) (io.ReadCloser, error) {
	logger().WithField("file", file).Info("starting processing of file")
	file = strings.TrimPrefix(file, "file://")

	return os.Open(file)
}

// downloads file (or reads local file) and writes each line in the file to the result channel
func (b *ListCache) parseFile(ctx context.Context, name, link string, resultCh chan<- string) error {
	count := 0

	logger := func() *logrus.Entry {
		return logger().WithFields(logrus.Fields{
			"source": name,
			"count":  count,
		})
	}

	r, err := b.newLinkReader(link)
	if err != nil {
		logger().Error("cannot open source: ", err)

		return err
	}
	defer r.Close()

	p := parsers.AllowErrors(parsers.Hosts(r), maxErrorsPerFile)
	p.OnErr(func(err error) {
		logger().Warnf("parse error: %s, trying to continue", err)
	})

	err = parsers.ForEach[*parsers.HostsIterator](ctx, p, func(hosts *parsers.HostsIterator) error {
		return hosts.ForEach(func(host string) error {
			count++

			// For IPs, we want to ensure the string is the Go representation so that when
			// we compare responses, a same IP matches, even if it was written differently
			// in the list.
			if ip := net.ParseIP(host); ip != nil {
				host = ip.String()
			}

			resultCh <- host

			return nil
		})
	})
	if err != nil {
		// Don't log cancelation: it was caused by another goroutine failing
		if !errors.Is(err, context.Canceled) {
			logger().Error("parse error: ", err)
		}

		// Only propagate the error if no entries were parsed
		// If the file was partially parsed, we'll settle for that

		if count == 0 {
			return err
		}

		return nil
	}

	logger().Info("import succeeded")

	return nil
}

func linkName(linkIdx int, link string) string {
	if strings.ContainsAny(link, "\n") {
		return fmt.Sprintf("inline block (item #%d in group)", linkIdx)
	}

	return link
}

func (b *ListCache) newLinkReader(link string) (r io.ReadCloser, err error) {
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
