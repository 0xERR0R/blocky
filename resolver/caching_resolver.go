package resolver

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/redis"
	"github.com/0xERR0R/blocky/util"
	expirationcache "github.com/0xERR0R/expiration-cache"

	"github.com/0xERR0R/blocky/cache"
	"github.com/0xERR0R/blocky/cache/prefetching"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

const defaultCachingCleanUpInterval = 5 * time.Second

//nolint:gochecknoglobals
var (
	cacheHits = promauto.With(metrics.Reg).NewCounter(
		prometheus.CounterOpts{
			Name: "blocky_cache_hits_total",
			Help: "Cache hit counter",
		},
	)
	cacheMisses = promauto.With(metrics.Reg).NewCounter(
		prometheus.CounterOpts{
			Name: "blocky_cache_misses_total",
			Help: "Cache miss counter",
		},
	)
)

// CachingResolver caches answers from dns queries with their TTL time,
// to avoid external resolver calls for recurrent queries
type CachingResolver struct {
	configurable[*config.Caching]
	NextResolver
	typed

	emitMetricEvents bool // disabled by Bootstrap

	resultCache cache.ExpiringCache[[]byte]

	redisClient *redis.Client

	compiledExclusions []*regexp.Regexp
}

// NewCachingResolver creates a new resolver instance
func NewCachingResolver(ctx context.Context,
	cfg config.Caching,
	redis *redis.Client,
) (*CachingResolver, error) {
	return newCachingResolver(ctx, cfg, redis, true)
}

func newCachingResolver(ctx context.Context,
	cfg config.Caching,
	redis *redis.Client,
	emitMetricEvents bool,
) (*CachingResolver, error) {
	c := &CachingResolver{
		configurable: withConfig(&cfg),
		typed:        withType("caching"),

		redisClient:      redis,
		emitMetricEvents: emitMetricEvents,
	}

	configureCaches(ctx, c, &cfg)
	err := configureExclusions(c, &cfg)

	if c.redisClient != nil {
		go c.redisSubscriber(ctx)
		c.redisClient.GetRedisCache(ctx)
	}

	return c, err
}

func configureCaches(ctx context.Context, c *CachingResolver, cfg *config.Caching) {
	options := expirationcache.Options{
		CleanupInterval: defaultCachingCleanUpInterval,
		MaxSize:         uint(cfg.MaxItemsCount),
		OnCacheHitFn: func(key string) {
			cacheHits.Inc()
		},
		OnCacheMissFn: func(key string) {
			cacheMisses.Inc()
		},
		OnAfterPutFn: func(newSize int) {
			c.publishMetricsIfEnabled(evt.CachingResultCacheChanged, newSize)
		},
	}

	if cfg.Prefetching {
		prefetchingOptions := prefetching.PrefetchingOptions[[]byte]{
			Options:               options,
			PrefetchExpires:       time.Duration(cfg.PrefetchExpires),
			PrefetchThreshold:     cfg.PrefetchThreshold,
			PrefetchMaxItemsCount: cfg.PrefetchMaxItemsCount,
			ReloadFn:              c.reloadCacheEntry,
			OnPrefetchAfterPut: func(newSize int) {
				c.publishMetricsIfEnabled(evt.CachingDomainsToPrefetchCountChanged, newSize)
			},
			OnPrefetchEntryReloaded: func(key string) {
				c.publishMetricsIfEnabled(evt.CachingDomainPrefetched, key)
			},
			OnPrefetchCacheHit: func(key string) {
				c.publishMetricsIfEnabled(evt.CachingPrefetchCacheHit, key)
			},
		}

		c.resultCache = prefetching.NewPrefetchingCache(ctx, prefetchingOptions)
	} else {
		c.resultCache = expirationcache.NewCache[[]byte](ctx, options)
	}
}

func configureExclusions(c *CachingResolver, cfg *config.Caching) error {
	compiled := []*regexp.Regexp{}
	for _, expStr := range cfg.Exclude {
		if !strings.HasPrefix(expStr, "/") || !strings.HasSuffix(expStr, "/") {
			return fmt.Errorf("cache exclusion configuration '%s' fail because of missing slashes", expStr)
		}
		re, err := regexp.Compile(strings.TrimSpace(expStr[1 : len(expStr)-1]))
		if err != nil {
			return fmt.Errorf("cache exclusion configuration '%s' fail because '%s'", expStr, err.Error())
		}
		compiled = append(compiled, re)
	}
	c.compiledExclusions = compiled

	return nil
}

func (r *CachingResolver) reloadCacheEntry(ctx context.Context, cacheKey string) (*[]byte, time.Duration) {
	qType, domainName := util.ExtractCacheKey(cacheKey)
	ctx, logger := r.log(ctx)

	logger.Debugf("prefetching '%s' (%s)", util.Obfuscate(domainName), qType)

	req := newRequest(dns.Fqdn(domainName), qType)
	response, err := r.next.Resolve(ctx, req)

	if err == nil {
		if response.Res.Rcode == dns.RcodeSuccess {
			packed, err := response.Res.Pack()
			if err != nil {
				logger.Error("unable to pack response", err)

				return nil, 0
			}

			return &packed, r.adjustTTLs(response.Res.Answer)
		}
	} else {
		util.LogOnError(ctx, fmt.Sprintf("can't prefetch '%s' ", domainName), err)
	}

	return nil, 0
}

func (r *CachingResolver) redisSubscriber(ctx context.Context) {
	ctx, logger := r.log(ctx)

	for {
		select {
		case rc := <-r.redisClient.CacheChannel:
			if rc != nil {
				logger.Debug("Received key from redis: ", rc.Key)
				ttl := r.adjustTTLs(rc.Response.Res.Answer)
				r.putInCache(ctx, rc.Key, rc.Response, ttl, false)
			}

		case <-ctx.Done():
			return
		}
	}
}

// LogConfig implements `config.Configurable`.
func (r *CachingResolver) LogConfig(logger *logrus.Entry) {
	r.cfg.LogConfig(logger)

	logger.Infof("cache entries = %d", r.resultCache.TotalCount())
}

// Resolve checks if the current query should use the cache and if the result is already in
// the cache and returns it or delegates to the next resolver
func (r *CachingResolver) Resolve(ctx context.Context, request *model.Request) (response *model.Response, err error) {
	ctx, logger := r.log(ctx)

	if !r.IsEnabled() || !r.isRequestCacheable(request) {
		logger.Debug("skip cache")

		return r.next.Resolve(ctx, request)
	}

	for _, question := range request.Req.Question {
		domain := util.ExtractDomain(question)
		cacheKey := util.GenerateCacheKey(dns.Type(question.Qtype), domain)
		logger := logger.WithField("domain", util.Obfuscate(domain))

		val, ttl := r.getFromCache(logger, cacheKey)

		if val != nil {
			logger.Debug("domain is cached")

			val.SetRcode(request.Req, val.Rcode)

			// Adjust TTL
			setTTLInCachedResponse(val, ttl)

			if val.Rcode == dns.RcodeSuccess {
				return &model.Response{Res: val, RType: model.ResponseTypeCACHED, Reason: "CACHED"}, nil
			}

			return &model.Response{Res: val, RType: model.ResponseTypeCACHED, Reason: "CACHED NEGATIVE"}, nil
		}

		logger.WithField("next_resolver", Name(r.next)).Trace("not in cache: go to next resolver")
		response, err = r.next.Resolve(ctx, request)

		if err == nil {
			cacheTTL := r.adjustTTLs(response.Res.Answer)
			r.putInCache(ctx, cacheKey, response, cacheTTL, true)
		}
	}

	return response, err
}

func (r *CachingResolver) getFromCache(logger *logrus.Entry, key string) (*dns.Msg, time.Duration) {
	val, ttl := r.resultCache.Get(key)
	if val == nil {
		return nil, 0
	}

	res := new(dns.Msg)

	err := res.Unpack(*val)
	if err != nil {
		logger.Error("can't unpack cached entry. Cache malformed?", err)

		return nil, 0
	}

	return res, ttl
}

func setTTLInCachedResponse(resp *dns.Msg, ttl time.Duration) {
	minTTL := uint32(math.MaxInt32)
	// find smallest TTL first
	for _, rr := range resp.Answer {
		minTTL = min(minTTL, rr.Header().Ttl)
	}

	for _, rr := range resp.Answer {
		rr.Header().Ttl = rr.Header().Ttl - minTTL + uint32(ttl.Seconds())
	}
}

// isRequestCacheable returns true if the request should be cached
func (r *CachingResolver) isRequestCacheable(request *model.Request) bool {
	// don't cache response if name ends with any exclution
	if questionsMatchAnyExcludedElement(request.Req.Question, r.compiledExclusions) {
		return false
	}
	// don't cache responses with EDNS Client Subnet option with masks that include more than one client
	if so := util.GetEdns0Option[*dns.EDNS0_SUBNET](request.Req); so != nil {
		if (so.Family == ecsFamilyIPv4 && so.SourceNetmask != ecsMaskIPv4) ||
			(so.Family == ecsFamilyIPv6 && so.SourceNetmask != ecsMaskIPv6) {
			return false
		}
	}

	return true
}

func questionsMatchAnyExcludedElement(questions []dns.Question, exclutions []*regexp.Regexp) bool {
	for _, q := range questions {
		if matchAnyElementOfArray(q.Name[:len(q.Name)-1], exclutions) {
			return true
		}
	}

	return false
}

func matchAnyElementOfArray(givingText string, arr []*regexp.Regexp) bool {
	loweredGivingText := strings.ToLower(givingText)
	for _, s := range arr {
		if s.MatchString(loweredGivingText) {
			return true
		}
	}

	return false
}

// isResponseCacheable returns true if the response is not truncated and its CD flag isn't set.
func isResponseCacheable(msg *dns.Msg) bool {
	// we don't cache truncated responses and responses with CD flag
	return !msg.Truncated && !msg.CheckingDisabled
}

func (r *CachingResolver) putInCache(
	ctx context.Context, cacheKey string, response *model.Response, ttl time.Duration, publish bool,
) {
	respCopy := response.Res.Copy()

	// don't cache any EDNS OPT records
	util.RemoveEdns0Record(respCopy)

	packed, err := respCopy.Pack()
	util.LogOnError(ctx, "error on packing", err)

	if err == nil {
		if response.Res.Rcode == dns.RcodeSuccess && isResponseCacheable(response.Res) {
			// put value into cache
			r.resultCache.Put(cacheKey, &packed, ttl)
		} else if response.Res.Rcode == dns.RcodeNameError {
			if r.cfg.CacheTimeNegative.IsAboveZero() {
				// put negative cache if result code is NXDOMAIN
				r.resultCache.Put(cacheKey, &packed, r.cfg.CacheTimeNegative.ToDuration())
			}
		}
	}

	if publish && r.redisClient != nil {
		res := *respCopy
		r.redisClient.PublishCache(cacheKey, &res)
	}
}

// adjustTTLs calculates and returns the min TTL (considers also the min and max cache time)
// for all records from answer or a negative cache time for empty answer
// adjust the TTL in the answer header accordingly
func (r *CachingResolver) adjustTTLs(answer []dns.RR) (ttl time.Duration) {
	minTTL := uint32(math.MaxInt32)

	if len(answer) == 0 {
		return r.cfg.CacheTimeNegative.ToDuration()
	}

	for _, a := range answer {
		// if TTL < mitTTL -> adjust the value, set minTTL
		if r.cfg.MinCachingTime.IsAboveZero() {
			if atomic.LoadUint32(&a.Header().Ttl) < r.cfg.MinCachingTime.SecondsU32() {
				atomic.StoreUint32(&a.Header().Ttl, r.cfg.MinCachingTime.SecondsU32())
			}
		}

		if r.cfg.MaxCachingTime.IsAboveZero() {
			if atomic.LoadUint32(&a.Header().Ttl) > r.cfg.MaxCachingTime.SecondsU32() {
				atomic.StoreUint32(&a.Header().Ttl, r.cfg.MaxCachingTime.SecondsU32())
			}
		}

		headerTTL := atomic.LoadUint32(&a.Header().Ttl)
		if minTTL > headerTTL {
			minTTL = headerTTL
		}
	}

	return time.Duration(minTTL) * time.Second
}

func (r *CachingResolver) publishMetricsIfEnabled(event string, val interface{}) {
	if r.emitMetricEvents {
		evt.Bus().Publish(event, val)
	}
}

func (r *CachingResolver) FlushCaches(ctx context.Context) {
	_, logger := r.log(ctx)

	logger.Debug("flush caches")
	r.resultCache.Clear()
}
