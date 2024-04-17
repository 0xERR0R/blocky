package resolver

import (
	"context"
	"time"

	"github.com/0xERR0R/blocky/cache/expirationcache"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/redis"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	defaultCachingCleanUpInterval = 5 * time.Second
	// noCacheTTL indicates that a response should not be cached
	noCacheTTL = uint32(0)
)

// CachingResolver caches answers from dns queries with their TTL time,
// to avoid external resolver calls for recurrent queries
type CachingResolver struct {
	configurable[*config.Caching]
	NextResolver
	typed

	emitMetricEvents bool // disabled by Bootstrap

	resultCache expirationcache.ExpiringCache[[]byte]

	redisClient *redis.Client
}

// NewCachingResolver creates a new resolver instance
func NewCachingResolver(ctx context.Context,
	cfg config.Caching,
	redis *redis.Client,
) *CachingResolver {
	return newCachingResolver(ctx, cfg, redis, true)
}

func newCachingResolver(ctx context.Context,
	cfg config.Caching,
	redis *redis.Client,
	emitMetricEvents bool,
) *CachingResolver {
	c := &CachingResolver{
		configurable: withConfig(&cfg),
		typed:        withType("caching"),

		redisClient:      redis,
		emitMetricEvents: emitMetricEvents,
	}

	configureCaches(ctx, c, &cfg)

	if c.redisClient != nil {
		go c.redisSubscriber(ctx)
		c.redisClient.GetRedisCache(ctx)
	}

	return c
}

func configureCaches(ctx context.Context, c *CachingResolver, cfg *config.Caching) {
	options := expirationcache.Options{
		CleanupInterval: defaultCachingCleanUpInterval,
		MaxSize:         uint(cfg.MaxItemsCount),
		OnCacheHitFn: func(key string) {
			c.publishMetricsIfEnabled(evt.CachingResultCacheHit, key)
		},
		OnCacheMissFn: func(key string) {
			c.publishMetricsIfEnabled(evt.CachingResultCacheMiss, key)
		},
		OnAfterPutFn: func(newSize int) {
			c.publishMetricsIfEnabled(evt.CachingResultCacheChanged, newSize)
		},
	}

	if cfg.Prefetching {
		prefetchingOptions := expirationcache.PrefetchingOptions[[]byte]{
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

		c.resultCache = expirationcache.NewPrefetchingCache(ctx, prefetchingOptions)
	} else {
		c.resultCache = expirationcache.NewCache[[]byte](ctx, options)
	}
}

func (r *CachingResolver) reloadCacheEntry(ctx context.Context, cacheKey string) (*[]byte, time.Duration) {
	qType, domainName := util.ExtractCacheKey(cacheKey)
	ctx, logger := r.log(ctx)
	logger = logger.WithField("domain", util.Obfuscate(domainName))

	logger.Debugf("prefetching %s", qType)

	req := newRequest(dns.Fqdn(domainName), qType)

	response, err := r.next.Resolve(ctx, req)
	if err != nil {
		logger.WithError(err).Warn("cache prefetch failed")

		return nil, 0
	}

	cacheCopy, ttl := r.createCacheEntry(logger, response.Res)
	if cacheCopy == nil || ttl == noCacheTTL {
		return nil, 0
	}

	packed, err := cacheCopy.Pack()
	if err != nil {
		logger.WithError(err).WithError(err).Warn("response packing failed")

		return nil, 0
	}

	if r.redisClient != nil {
		r.redisClient.PublishCache(cacheKey, cacheCopy)
	}

	return &packed, time.Duration(ttl) * time.Second
}

func (r *CachingResolver) redisSubscriber(ctx context.Context) {
	ctx, logger := r.log(ctx)

	for {
		select {
		case rc := <-r.redisClient.CacheChannel:
			if rc != nil {
				_, domain := util.ExtractCacheKey(rc.Key)

				dlogger := logger.WithField("domain", util.Obfuscate(domain))

				dlogger.Debug("received from redis")

				r.putInCache(dlogger, rc.Key, rc.Response)
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

	if !r.IsEnabled() || !isRequestCacheable(request) {
		logger.Debug("skip cache")

		return r.next.Resolve(ctx, request)
	}

	for _, question := range request.Req.Question {
		domain := util.ExtractDomain(question)
		cacheKey := util.GenerateCacheKey(dns.Type(question.Qtype), domain)
		logger := logger.WithField("domain", util.Obfuscate(domain))

		cacheEntry := r.getFromCache(logger, cacheKey)

		if cacheEntry != nil {
			logger.Debug("domain is cached")

			cacheEntry.SetRcode(request.Req, cacheEntry.Rcode)

			if cacheEntry.Rcode == dns.RcodeSuccess {
				return &model.Response{Res: cacheEntry, RType: model.ResponseTypeCACHED, Reason: "CACHED"}, nil
			}

			return &model.Response{Res: cacheEntry, RType: model.ResponseTypeCACHED, Reason: "CACHED NEGATIVE"}, nil
		}

		logger.WithField("next_resolver", Name(r.next)).Trace("not in cache: go to next resolver")

		response, err = r.next.Resolve(ctx, request)
		if err == nil {
			ttl := r.modifyResponseTTL(response.Res)
			if ttl > noCacheTTL {
				cacheCopy := r.putInCache(logger, cacheKey, response)
				if cacheCopy != nil && r.redisClient != nil {
					r.redisClient.PublishCache(cacheKey, cacheCopy)
				}
			}
		}
	}

	return response, err
}

func (r *CachingResolver) getFromCache(logger *logrus.Entry, key string) *dns.Msg {
	raw, ttl := r.resultCache.Get(key)
	if raw == nil {
		return nil
	}

	res := new(dns.Msg)

	err := res.Unpack(*raw)
	if err != nil {
		logger.Error("can't unpack cached entry. Cache malformed?", err)

		return nil
	}

	// Adjust TTL
	util.AdjustAnswerTTL(res, ttl)

	return res
}

// isRequestCacheable returns true if the request should be cached
func isRequestCacheable(request *model.Request) bool {
	// don't cache responses with EDNS Client Subnet option with masks that include more than one client
	if so := util.GetEdns0Option[*dns.EDNS0_SUBNET](request.Req); so != nil {
		if (so.Family == ecsFamilyIPv4 && so.SourceNetmask != ecsMaskIPv4) ||
			(so.Family == ecsFamilyIPv6 && so.SourceNetmask != ecsMaskIPv6) {
			return false
		}
	}

	return true
}

func (r *CachingResolver) putInCache(logger *logrus.Entry, cacheKey string, response *model.Response) *dns.Msg {
	cacheCopy, ttl := r.createCacheEntry(logger, response.Res)
	if cacheCopy == nil || ttl == noCacheTTL {
		return nil
	}

	packed, err := cacheCopy.Pack()
	if err != nil {
		logger.WithError(err).Warn("response packing failed")

		return nil
	}

	r.resultCache.Put(cacheKey, &packed, time.Duration(ttl)*time.Second)

	return cacheCopy
}

func (r *CachingResolver) modifyResponseTTL(response *dns.Msg) uint32 {
	// if response is empty or negative, return negative cache time from config
	if len(response.Answer) == 0 || response.Rcode == dns.RcodeNameError {
		return util.ToTTL(r.cfg.CacheTimeNegative)
	}

	// if response is truncated or CD flag is set, return noCacheTTL since we don't cache these responses
	if response.Truncated || response.CheckingDisabled {
		return 0
	}

	// if response is not successful, return noCacheTTL since we don't cache these responses
	if response.Rcode != dns.RcodeSuccess {
		return 0
	}

	// adjust TTLs of all answers to match the configured min and max caching times
	util.SetAnswerMinMaxTTL(response, r.cfg.MinCachingTime, r.cfg.MaxCachingTime)

	return util.GetAnswerMinTTL(response)
}

func (r *CachingResolver) createCacheEntry(logger *logrus.Entry, input *dns.Msg,
) (*dns.Msg, uint32) {
	response := input.Copy()

	ttl := r.modifyResponseTTL(response)
	if ttl == noCacheTTL {
		logger.Debug("response is not cacheable")

		return nil, 0
	}

	// don't cache any EDNS OPT records
	util.RemoveEdns0Record(response)

	return response, ttl
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
