package resolver

import (
	"blocky/util"
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

// caches answers from dns queries with their TTL time, to avoid external resolver calls for recurrent queries
type CachingResolver struct {
	NextResolver
	cachesPerType map[uint16]*cache.Cache
}

const (
	minTTL            = 250
	cacheTimeNegative = 30 * time.Minute
)

type Type uint8

const (
	A Type = iota
	AAAA
)

func NewCachingResolver() ChainedResolver {
	return &CachingResolver{
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
	for t, cache := range r.cachesPerType {
		result = append(result, fmt.Sprintf("%s cache items count = %d", dns.TypeToString[t], cache.ItemCount()))
	}

	return
}

func (r *CachingResolver) Resolve(request *Request) (response *Response, err error) {
	logger := withPrefix(request.Log, "caching_resolver")

	resp := new(dns.Msg)
	resp.SetReply(request.Req)

	for _, question := range request.Req.Question {
		domain := util.ExtractDomain(question)
		logger := logger.WithField("domain", domain)

		// we caching only A and AAAA queries
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

					return &Response{Res: resp, Reason: fmt.Sprintf("CACHED (ttl %d)", remainingTTL)}, nil
				}
				// Answer with response code != OK
				resp.Rcode = val.(int)

				return &Response{Res: resp, Reason: fmt.Sprintf("CACHED NEGATIVE (ttl %d)", remainingTTL)}, nil
			}

			logger.WithField("next_resolver", r.next).Debug("not in cache: go to next resolver")
			response, err = r.next.Resolve(request)

			if err == nil {
				answer := response.Res.Answer

				var maxTTL = adjustTTLs(answer)

				if response.Res.Rcode == dns.RcodeSuccess {
					// put value into cache
					r.getCache(question.Qtype).Set(domain, answer, time.Duration(maxTTL)*time.Second)
				} else if response.Res.Rcode == dns.RcodeNameError {
					// put return code if NXDOMAIN
					r.getCache(question.Qtype).Set(domain, response.Res.Rcode, cacheTimeNegative)
				}
			}
		} else {
			logger.Debugf("not A/AAAA: go to next %s", r.next)
			return r.next.Resolve(request)
		}
	}

	return response, err
}

func adjustTTLs(answer []dns.RR) (maxTTL uint32) {
	for _, a := range answer {
		// if TTL < mitTTL -> adjust the value, set minTTL
		if a.Header().Ttl < minTTL {
			a.Header().Ttl = minTTL
		}

		if maxTTL < a.Header().Ttl {
			maxTTL = a.Header().Ttl
		}
	}

	return
}

func (r CachingResolver) String() string {
	return fmt.Sprintf("caching resolver")
}
