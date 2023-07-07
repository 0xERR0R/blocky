package resolver

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/cache/expirationcache"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/redis"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const defaultCachingCleanUpInterval = 5 * time.Second

// CachingResolver caches answers from dns queries with their TTL time,
// to avoid external resolver calls for recurrent queries
type CachingResolver struct {
	configurable[*config.CachingConfig]
	NextResolver
	typed

	emitMetricEvents bool // disabled by Bootstrap

	resultCache          expirationcache.ExpiringCache[cacheValue]
	prefetchingNameCache expirationcache.ExpiringCache[int]
	redisClient          *redis.Client
}

// cacheValue includes query answer and prefetch flag
type cacheValue struct {
	resultMsg *dns.Msg
	prefetch  bool
}

// NewCachingResolver creates a new resolver instance
func NewCachingResolver(cfg config.CachingConfig, redis *redis.Client) *CachingResolver {
	return newCachingResolver(cfg, redis, true)
}

func newCachingResolver(cfg config.CachingConfig, redis *redis.Client, emitMetricEvents bool) *CachingResolver {
	c := &CachingResolver{
		configurable: withConfig(&cfg),
		typed:        withType("caching"),

		redisClient:      redis,
		emitMetricEvents: emitMetricEvents,
	}

	configureCaches(c, &cfg)

	if c.redisClient != nil {
		setupRedisCacheSubscriber(c)
		c.redisClient.GetRedisCache()
	}

	return c
}

func configureCaches(c *CachingResolver, cfg *config.CachingConfig) {
	cleanupOption := expirationcache.WithCleanUpInterval[cacheValue](defaultCachingCleanUpInterval)
	maxSizeOption := expirationcache.WithMaxSize[cacheValue](uint(cfg.MaxItemsCount))

	if cfg.Prefetching {
		c.prefetchingNameCache = expirationcache.NewCache(
			expirationcache.WithCleanUpInterval[int](time.Minute),
			expirationcache.WithMaxSize[int](uint(cfg.PrefetchMaxItemsCount)),
		)

		c.resultCache = expirationcache.NewCache(
			cleanupOption,
			maxSizeOption,
			expirationcache.WithOnExpiredFn(c.onExpired),
		)
	} else {
		c.resultCache = expirationcache.NewCache(cleanupOption, maxSizeOption)
	}
}

func setupRedisCacheSubscriber(c *CachingResolver) {
	go func() {
		for rc := range c.redisClient.CacheChannel {
			if rc != nil {
				c.log().Debug("Received key from redis: ", rc.Key)
				c.putInCache(rc.Key, rc.Response, false, false)
			}
		}
	}()
}

// check if domain was queried > threshold in the time window
func (r *CachingResolver) shouldPrefetch(cacheKey string) bool {
	if r.cfg.PrefetchThreshold == 0 {
		return true
	}

	cnt, _ := r.prefetchingNameCache.Get(cacheKey)

	return cnt != nil && *cnt > r.cfg.PrefetchThreshold
}

func (r *CachingResolver) onExpired(cacheKey string) (val *cacheValue, ttl time.Duration) {
	qType, domainName := util.ExtractCacheKey(cacheKey)

	if r.shouldPrefetch(cacheKey) {
		logger := r.log()

		logger.Debugf("prefetching '%s' (%s)", util.Obfuscate(domainName), qType)

		req := newRequest(fmt.Sprintf("%s.", domainName), qType, logger)
		response, err := r.next.Resolve(req)

		if err == nil {
			if response.Res.Rcode == dns.RcodeSuccess {
				r.publishMetricsIfEnabled(evt.CachingDomainPrefetched, domainName)

				return &cacheValue{response.Res, true}, r.adjustTTLs(response.Res.Answer)
			}
		} else {
			util.LogOnError(fmt.Sprintf("can't prefetch '%s' ", domainName), err)
		}
	}

	return nil, 0
}

// LogConfig implements `config.Configurable`.
func (r *CachingResolver) LogConfig(logger *logrus.Entry) {
	r.cfg.LogConfig(logger)

	logger.Infof("cache entries = %d", r.resultCache.TotalCount())
}

// Resolve checks if the current query result is already in the cache and returns it
// or delegates to the next resolver
func (r *CachingResolver) Resolve(request *model.Request) (response *model.Response, err error) {
	logger := log.WithPrefix(request.Log, "caching_resolver")

	if r.cfg.MaxCachingTime < 0 {
		logger.Debug("skip cache")

		return r.next.Resolve(request)
	}

	for _, question := range request.Req.Question {
		domain := util.ExtractDomain(question)
		cacheKey := util.GenerateCacheKey(dns.Type(question.Qtype), domain)
		logger := logger.WithField("domain", util.Obfuscate(domain))

		r.trackQueryDomainNameCount(domain, cacheKey, logger)

		val, ttl := r.resultCache.Get(cacheKey)

		if val != nil {
			logger.Debug("domain is cached")

			r.publishMetricsIfEnabled(evt.CachingResultCacheHit, domain)

			if val.prefetch {
				// Hit from prefetch cache
				r.publishMetricsIfEnabled(evt.CachingPrefetchCacheHit, domain)
			}

			resp := val.resultMsg.Copy()
			resp.SetReply(request.Req)
			resp.Rcode = val.resultMsg.Rcode

			// Adjust TTL
			for _, rr := range resp.Answer {
				rr.Header().Ttl = uint32(ttl.Seconds())
			}

			if resp.Rcode == dns.RcodeSuccess {
				return &model.Response{Res: resp, RType: model.ResponseTypeCACHED, Reason: "CACHED"}, nil
			}

			return &model.Response{Res: resp, RType: model.ResponseTypeCACHED, Reason: "CACHED NEGATIVE"}, nil
		}

		r.publishMetricsIfEnabled(evt.CachingResultCacheMiss, domain)

		logger.WithField("next_resolver", Name(r.next)).Debug("not in cache: go to next resolver")
		response, err = r.next.Resolve(request)

		if err == nil {
			r.putInCache(cacheKey, response, false, true)
		}
	}

	return response, err
}

func (r *CachingResolver) trackQueryDomainNameCount(domain, cacheKey string, logger *logrus.Entry) {
	if r.prefetchingNameCache != nil {
		var domainCount int
		if x, _ := r.prefetchingNameCache.Get(cacheKey); x != nil {
			domainCount = *x
		}
		domainCount++
		r.prefetchingNameCache.Put(cacheKey, &domainCount, r.cfg.PrefetchExpires.ToDuration())
		totalCount := r.prefetchingNameCache.TotalCount()

		logger.Debugf("domain '%s' was requested %d times, "+
			"total cache size: %d", util.Obfuscate(domain), domainCount, totalCount)
		r.publishMetricsIfEnabled(evt.CachingDomainsToPrefetchCountChanged, totalCount)
	}
}

func (r *CachingResolver) putInCache(cacheKey string, response *model.Response, prefetch, publish bool) {
	if response.Res.Rcode == dns.RcodeSuccess {
		// put value into cache
		r.resultCache.Put(cacheKey, &cacheValue{response.Res, prefetch}, r.adjustTTLs(response.Res.Answer))
	} else if response.Res.Rcode == dns.RcodeNameError {
		if r.cfg.CacheTimeNegative.IsAboveZero() {
			// put negative cache if result code is NXDOMAIN
			r.resultCache.Put(cacheKey, &cacheValue{response.Res, prefetch}, r.cfg.CacheTimeNegative.ToDuration())
		}
	}

	r.publishMetricsIfEnabled(evt.CachingResultCacheChanged, r.resultCache.TotalCount())

	if publish && r.redisClient != nil {
		res := *response.Res
		res.Answer = response.Res.Answer
		r.redisClient.PublishCache(cacheKey, &res)
	}
}

// adjustTTLs calculates and returns the max TTL (considers also the min and max cache time)
// for all records from answer or a negative cache time for empty answer
// adjust the TTL in the answer header accordingly
func (r *CachingResolver) adjustTTLs(answer []dns.RR) (maxTTL time.Duration) {
	var max uint32

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
		if max < headerTTL {
			max = headerTTL
		}
	}

	return time.Duration(max) * time.Second
}

func (r *CachingResolver) publishMetricsIfEnabled(event string, val interface{}) {
	if r.emitMetricEvents {
		evt.Bus().Publish(event, val)
	}
}
