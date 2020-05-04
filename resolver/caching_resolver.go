package resolver

import (
	"blocky/config"
	"blocky/util"
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

// caches answers from dns queries with their TTL time, to avoid external resolver calls for recurrent queries
type CachingResolver struct {
	NextResolver
	minCacheTimeSec, maxCacheTimeSec int
	cachesPerType                    map[uint16]*cache.Cache
}

const (
	cacheTimeNegative = 30 * time.Minute
)

func NewCachingResolver(cfg config.CachingConfig) ChainedResolver {
	return &CachingResolver{
		minCacheTimeSec: 60 * cfg.MinCachingTime,
		maxCacheTimeSec: 60 * cfg.MaxCachingTime,
		cachesPerType: map[uint16]*cache.Cache{
			dns.TypeA:    cache.New(15*time.Minute, 5*time.Minute),
			dns.TypeAAAA: cache.New(15*time.Minute, 5*time.Minute),
		},
	}
}

func (r *CachingResolver) getCache(queryType uint16) *cache.Cache {
	return r.cachesPerType[queryType]
}

func (r *CachingResolver) Configuration() (result []string) {
	if r.maxCacheTimeSec < 0 {
		result = []string{"deactivated"}
		return
	}

	result = append(result, fmt.Sprintf("minCacheTimeInSec = %d", r.minCacheTimeSec))

	result = append(result, fmt.Sprintf("maxCacheTimeSec = %d", r.maxCacheTimeSec))

	for t, c := range r.cachesPerType {
		result = append(result, fmt.Sprintf("%s cache items count = %d", dns.TypeToString[t], c.ItemCount()))
	}

	return
}

func (r *CachingResolver) Resolve(request *Request) (response *Response, err error) {
	logger := withPrefix(request.Log, "caching_resolver")

	if r.maxCacheTimeSec < 0 {
		logger.Debug("skip cache")
		return r.next.Resolve(request)
	}

	resp := new(dns.Msg)
	resp.SetReply(request.Req)

	for _, question := range request.Req.Question {
		domain := util.ExtractDomain(question)
		logger := logger.WithField("domain", domain)

		// we can cache only A and AAAA queries
		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
			val, expiresAt, found := r.getCache(question.Qtype).GetWithExpiration(domain)

			if found {
				logger.Debug("domain is cached")

				// calculate remaining TTL
				remainingTTL := uint32(time.Until(expiresAt).Seconds())

				v, ok := val.([]dns.RR)
				if ok {
					// Answer from successful request
					resp.Answer = v
					for _, rr := range resp.Answer {
						rr.Header().Ttl = remainingTTL
					}

					return &Response{Res: resp, RType: CACHED, Reason: "CACHED"}, nil
				}
				// Answer with response code != OK
				resp.Rcode = val.(int)

				return &Response{Res: resp, RType: CACHED, Reason: "CACHED NEGATIVE"}, nil
			}

			logger.WithField("next_resolver", Name(r.next)).Debug("not in cache: go to next resolver")
			response, err = r.next.Resolve(request)

			if err == nil {
				r.putInCache(response, domain, question.Qtype)
			}
		} else {
			logger.Debugf("not A/AAAA: go to next %s", r.next)
			return r.next.Resolve(request)
		}
	}

	return response, err
}

func (r *CachingResolver) putInCache(response *Response, domain string, qType uint16) {
	answer := response.Res.Answer

	if response.Res.Rcode == dns.RcodeSuccess {
		// put value into cache
		r.getCache(qType).Set(domain, answer, time.Duration(r.adjustTTLs(answer))*time.Second)
	} else if response.Res.Rcode == dns.RcodeNameError {
		// put return code if NXDOMAIN
		r.getCache(qType).Set(domain, response.Res.Rcode, cacheTimeNegative)
	}
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
