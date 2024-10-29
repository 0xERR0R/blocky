package lists

//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names
import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/0xERR0R/blocky/cache/stringcache"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/lists/parsers"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/metrics"

	"github.com/ThinkChaos/parcour"
	"github.com/ThinkChaos/parcour/jobgroup"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

const (
	groupProducersBufferCap = 1000
	regexWarningThreshold   = 500
)

//nolint:gochecknoglobals
var (
	lastListGroupRefreshTimestamp = promauto.With(metrics.Reg).NewGauge(
		prometheus.GaugeOpts{
			Name: "blocky_last_list_group_refresh_timestamp_seconds",
			Help: "Timestamp of last list refresh",
		},
	)
	denylistEntries = promauto.With(metrics.Reg).NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "blocky_denylist_cache_entries",
			Help: "Number of entries in the denylist cache",
		}, []string{"group"},
	)
	allowlistEntries = promauto.With(metrics.Reg).NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "blocky_allowlist_cache_entries",
			Help: "Number of entries in the allowlist cache",
		}, []string{"group"},
	)
)

// ListCacheType represents the type of cached list ENUM(
// denylist // is a list with blocked domains
// allowlist // is a list with allowlisted domains / IPs
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
	regexCache   stringcache.GroupedStringCache

	cfg          config.SourceLoading
	listType     ListCacheType
	groupSources map[string][]config.BytesSource
	downloader   FileDownloader
}

// LogConfig implements `config.Configurable`.
func (b *ListCache) LogConfig(logger *logrus.Entry) {
	total := 0
	regexes := 0

	for group := range b.groupSources {
		count := b.groupedCache.ElementCount(group)
		logger.Infof("%s: %d entries", group, count)
		total += count
		regexes += b.regexCache.ElementCount(group)
	}

	if regexes > regexWarningThreshold {
		logger.Warnf(
			"REGEXES: %d !! High use of regexes is not recommended: they use a lot of memory and are very slow to search",
			regexes,
		)
	}

	logger.Infof("TOTAL: %d entries", total)
}

// NewListCache creates new list instance
func NewListCache(ctx context.Context,
	t ListCacheType, cfg config.SourceLoading,
	groupSources map[string][]config.BytesSource, downloader FileDownloader,
) (*ListCache, error) {
	regexCache := stringcache.NewInMemoryGroupedRegexCache()

	c := &ListCache{
		groupedCache: stringcache.NewChainedGroupedCache(
			regexCache,
			stringcache.NewInMemoryGroupedWildcardCache(), // must be after regex which can contain '*'
			stringcache.NewInMemoryGroupedStringCache(),   // accepts all values, must be last
		),
		regexCache: regexCache,

		cfg:          cfg,
		listType:     t,
		groupSources: groupSources,
		downloader:   downloader,
	}

	err := cfg.StartPeriodicRefresh(ctx, c.refresh, func(err error) {
		logger().WithError(err).Errorf("could not init %s", t)
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}

func logger() *logrus.Entry {
	return log.PrefixedLog("list_cache")
}

// Match matches passed domain name against cached list entries
func (b *ListCache) Match(domain string, groupsToCheck []string) (groups []string) {
	return b.groupedCache.Contains(domain, groupsToCheck)
}

// Refresh triggers the refresh of a list
func (b *ListCache) Refresh() error {
	return b.refresh(context.Background())
}

func (b *ListCache) refresh(ctx context.Context) error {
	unlimitedGrp, _ := jobgroup.WithContext(ctx)
	defer unlimitedGrp.Close()

	producersGrp := jobgroup.WithMaxConcurrency(unlimitedGrp, b.cfg.Concurrency)
	defer producersGrp.Close()

	for group, sources := range b.groupSources {
		group, sources := group, sources

		unlimitedGrp.Go(func(ctx context.Context) error {
			err := b.createCacheForGroup(producersGrp, unlimitedGrp, group, sources)
			if err != nil {
				count := b.groupedCache.ElementCount(group)

				logger := logger().WithFields(logrus.Fields{
					"group":       group,
					"total_count": count,
				})

				if count == 0 {
					logger.Warn("Populating of group cache failed, cache will be empty until refresh succeeds")
				} else {
					logger.Warn("Populating of group cache failed, using existing cache, if any")
				}

				return err
			}

			count := b.groupedCache.ElementCount(group)

			updateGroupMetrics(b.listType, group, count)

			logger().WithFields(logrus.Fields{
				"group":       group,
				"total_count": count,
			}).Info("group import finished")

			return nil
		})
	}

	return unlimitedGrp.Wait()
}

func (b *ListCache) createCacheForGroup(
	producersGrp, consumersGrp jobgroup.JobGroup, group string, sources []config.BytesSource,
) error {
	groupFactory := b.groupedCache.Refresh(group)

	producers := parcour.NewProducersWithBuffer[string](producersGrp, consumersGrp, groupProducersBufferCap)
	defer producers.Close()

	for i, source := range sources {
		i, source := i, source

		producers.GoProduce(func(ctx context.Context, hostsChan chan<- string) error {
			locInfo := fmt.Sprintf("item #%d of group %s", i, group)

			opener, err := NewSourceOpener(locInfo, source, b.downloader)
			if err != nil {
				return err
			}

			return b.parseFile(ctx, opener, hostsChan)
		})
	}

	hasEntries := false

	producers.GoConsume(func(ctx context.Context, ch <-chan string) error {
		for host := range ch {
			if groupFactory.AddEntry(host) {
				hasEntries = true
			} else {
				logger().WithField("host", host).Warn("no list cache was able to use host")
			}
		}

		return nil
	})

	err := producers.Wait()
	if err != nil {
		if !hasEntries {
			// Always fail the group if no entries were parsed
			return err
		}

		var transientErr *TransientError

		if errors.As(err, &transientErr) {
			// Temporary error: fail the whole group to retry later
			return err
		}
	}

	groupFactory.Finish()

	return nil
}

// downloads file (or reads local file) and writes each line in the file to the result channel
func (b *ListCache) parseFile(ctx context.Context, opener SourceOpener, resultCh chan<- string) error {
	count := 0

	logger := func() *logrus.Entry {
		return logger().WithFields(logrus.Fields{
			"source": opener.String(),
			"count":  count,
		})
	}

	logger().Debug("starting processing of source")

	r, err := opener.Open(ctx)
	if err != nil {
		logger().Error("cannot open source: ", err)

		return err
	}
	defer r.Close()

	p := parsers.AllowErrors(parsers.Hosts(r), b.cfg.MaxErrorsPerSource)
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

func updateGroupMetrics(listType ListCacheType, group string, count int) {
	lastListGroupRefreshTimestamp.Set(float64(time.Now().Unix()))

	switch listType {
	case ListCacheTypeDenylist:
		denylistEntries.WithLabelValues(group).Set(float64(count))
	case ListCacheTypeAllowlist:
		allowlistEntries.WithLabelValues(group).Set(float64(count))
	}
}
