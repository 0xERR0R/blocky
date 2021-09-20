package resolver

import (
	"fmt"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/0xERR0R/go-cache"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// CachingResolver caches answers from dns queries with their TTL time,
// to avoid external resolver calls for recurrent queries
type CachingResolver struct {
	NextResolver
	minCacheTimeSec, maxCacheTimeSec int
	resultCache                      *cache.Cache
	prefetchExpires                  time.Duration
	prefetchThreshold                int
	prefetchingNameCache             *cache.Cache
}

// cacheValue includes query answer and prefetch flag
type cacheValue struct {
	answer   []dns.RR
	prefetch bool
}

const (
	cacheTimeNegative              = 30 * time.Minute
	prefetchingNameCacheExpiration = 2 * time.Hour
	prefetchingNameCountThreshold  = 5
)

// NewCachingResolver creates a new resolver instance
func NewCachingResolver(cfg config.CachingConfig) ChainedResolver {
	c := &CachingResolver{
		minCacheTimeSec: int(time.Duration(cfg.MinCachingTime).Seconds()),
		maxCacheTimeSec: int(time.Duration(cfg.MaxCachingTime).Seconds()),
		resultCache:     createQueryResultCache(&cfg),
	}

	if cfg.Prefetching {
		configurePrefetching(c, &cfg)
	}

	return c
}

func createQueryResultCache(cfg *config.CachingConfig) *cache.Cache {
	return cache.NewWithLRU(15*time.Minute, 15*time.Second, cfg.MaxItemsCount)
}

func configurePrefetching(c *CachingResolver, cfg *config.CachingConfig) {
	c.prefetchExpires = prefetchingNameCacheExpiration
	if cfg.PrefetchExpires > 0 {
		c.prefetchExpires = time.Duration(cfg.PrefetchExpires)
	}

	c.prefetchThreshold = prefetchingNameCountThreshold
	if cfg.PrefetchThreshold > 0 {
		c.prefetchThreshold = cfg.PrefetchThreshold
	}

	c.prefetchingNameCache = cache.NewWithLRU(c.prefetchExpires, time.Minute, cfg.PrefetchMaxItemsCount)

	c.resultCache.OnEvicted(func(key string, i interface{}) {
		c.onEvicted(key)
	})
}

// onEvicted is called if a DNS response in the cache is expired and was removed from cache
func (r *CachingResolver) onEvicted(cacheKey string) {
	qType, domainName := util.ExtractCacheKey(cacheKey)
	logger := logger("caching_resolver")

	cnt, found := r.prefetchingNameCache.Get(cacheKey)

	// check if domain was queried > threshold in the time window
	if found && cnt.(int) > r.prefetchThreshold {
		logger.Debugf("prefetching '%s' (%s)", util.Obfuscate(domainName), dns.TypeToString[qType])

		req := newRequest(fmt.Sprintf("%s.", domainName), qType, logger)
		response, err := r.next.Resolve(req)

		if err == nil {
			r.putInCache(cacheKey, response, true)

			evt.Bus().Publish(evt.CachingDomainPrefetched, domainName)
		}

		util.LogOnError(fmt.Sprintf("can't prefetch '%s' ", domainName), err)
	}
}

// Configuration returns a current resolver configuration
func (r *CachingResolver) Configuration() (result []string) {
	if r.maxCacheTimeSec < 0 {
		result = []string{"deactivated"}
		return
	}

	result = append(result, fmt.Sprintf("minCacheTimeInSec = %d", r.minCacheTimeSec))

	result = append(result, fmt.Sprintf("maxCacheTimeSec = %d", r.maxCacheTimeSec))

	result = append(result, fmt.Sprintf("prefetching = %t", r.prefetchingNameCache != nil))

	if r.prefetchingNameCache != nil {
		result = append(result, fmt.Sprintf("prefetchExpires = %s", r.prefetchExpires))
		result = append(result, fmt.Sprintf("prefetchThreshold = %d", r.prefetchThreshold))
	}

	result = append(result, fmt.Sprintf("cache items count = %d", r.resultCache.ItemCount()))

	return
}

// Resolve checks if the current query result is already in the cache and returns it
// or delegates to the next resolver
//nolint:gocognit,funlen
func (r *CachingResolver) Resolve(request *model.Request) (response *model.Response, err error) {
	logger := withPrefix(request.Log, "caching_resolver")

	if r.maxCacheTimeSec < 0 {
		logger.Debug("skip cache")
		return r.next.Resolve(request)
	}

	resp := new(dns.Msg)
	resp.SetReply(request.Req)

	for _, question := range request.Req.Question {
		domain := util.ExtractDomain(question)
		cacheKey := util.GenerateCacheKey(question.Qtype, domain)
		logger := logger.WithField("domain", util.Obfuscate(domain))

		r.trackQueryDomainNameCount(domain, cacheKey, logger)

		val, expiresAt, found := r.resultCache.GetWithExpiration(cacheKey)

		if found {
			logger.Debug("domain is cached")

			evt.Bus().Publish(evt.CachingResultCacheHit, domain)

			// calculate remaining TTL
			remainingTTL := uint32(time.Until(expiresAt).Seconds())

			v, ok := val.(cacheValue)
			if ok {
				if v.prefetch {
					// Hit from prefetch cache
					evt.Bus().Publish(evt.CachingPrefetchCacheHit, domain)
				}

				// Answer from successful request
				resp.Answer = v.answer
				for _, rr := range resp.Answer {
					rr.Header().Ttl = remainingTTL
				}

				return &model.Response{Res: resp, RType: model.ResponseTypeCACHED, Reason: "CACHED"}, nil
			}
			// Answer with response code != OK
			resp.Rcode = val.(int)

			return &model.Response{Res: resp, RType: model.ResponseTypeCACHED, Reason: "CACHED NEGATIVE"}, nil
		}

		evt.Bus().Publish(evt.CachingResultCacheMiss, domain)

		logger.WithField("next_resolver", Name(r.next)).Debug("not in cache: go to next resolver")
		response, err = r.next.Resolve(request)

		if err == nil {
			r.putInCache(cacheKey, response, false)
		}
	}

	return response, err
}

func (r *CachingResolver) trackQueryDomainNameCount(domain string, cacheKey string, logger *logrus.Entry) {
	if r.prefetchingNameCache != nil {
		var domainCount int
		if x, found := r.prefetchingNameCache.Get(cacheKey); found {
			domainCount = x.(int)
		}
		domainCount++
		r.prefetchingNameCache.SetDefault(cacheKey, domainCount)
		logger.Debugf("domain '%s' was requested %d times, "+
			"total cache size: %d", util.Obfuscate(domain), domainCount, r.prefetchingNameCache.ItemCount())
		evt.Bus().Publish(evt.CachingDomainsToPrefetchCountChanged, r.prefetchingNameCache.ItemCount())
	}
}

func (r *CachingResolver) putInCache(cacheKey string, response *model.Response, prefetch bool) {
	answer := response.Res.Answer

	if response.Res.Rcode == dns.RcodeSuccess {
		// put value into cache
		r.resultCache.Set(cacheKey, cacheValue{answer, prefetch}, time.Duration(r.adjustTTLs(answer))*time.Second)
	} else if response.Res.Rcode == dns.RcodeNameError {
		// put return code if NXDOMAIN
		r.resultCache.Set(cacheKey, response.Res.Rcode, cacheTimeNegative)
	}

	evt.Bus().Publish(evt.CachingResultCacheChanged, r.resultCache.ItemCount())
}

func (r *CachingResolver) adjustTTLs(answer []dns.RR) (maxTTL uint32) {
	for _, a := range answer {
		// if TTL < mitTTL -> adjust the value, set minTTL
		if r.minCacheTimeSec > 0 {
			if a.Header().Ttl < uint32(r.minCacheTimeSec) {
				a.Header().Ttl = uint32(r.minCacheTimeSec)
			}
		}

		if r.maxCacheTimeSec > 0 {
			if a.Header().Ttl > uint32(r.maxCacheTimeSec) {
				a.Header().Ttl = uint32(r.maxCacheTimeSec)
			}
		}

		if maxTTL < a.Header().Ttl {
			maxTTL = a.Header().Ttl
		}
	}

	return
}
