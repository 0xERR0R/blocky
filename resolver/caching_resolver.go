package resolver

import (
	"blocky/util"
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

// caches answers from dns queries with their TTL time, to avoid external resolver calls for recurrent queries
type CachingResolver struct {
	NextResolver
	cacheA    *cache.Cache
	cacheAAAA *cache.Cache
}

const minTTL = 250

type Type uint8

const (
	A Type = iota
	AAAA
)

func NewCachingResolver() ChainedResolver {
	return &CachingResolver{
		cacheA:    cache.New(15*time.Minute, 5*time.Minute),
		cacheAAAA: cache.New(15*time.Minute, 5*time.Minute),
	}
}

func (r *CachingResolver) getCache(queryType uint16) *cache.Cache {
	switch queryType {
	case dns.TypeA:
		return r.cacheA
	case dns.TypeAAAA:
		return r.cacheAAAA
	default:
		log.Error("unknown type: ", queryType)
	}

	return r.cacheA
}

func (r *CachingResolver) Configuration() (result []string) {
	result = append(result, fmt.Sprintf("A cache items count = %d", r.cacheA.ItemCount()))
	result = append(result, fmt.Sprintf("AAAA cache items count = %d", r.cacheAAAA.ItemCount()))

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

				resp.Answer = val.([]dns.RR)
				for _, rr := range resp.Answer {
					rr.Header().Ttl = remainingTTL
				}

				return &Response{Res: resp, Reason: fmt.Sprintf("CACHED (ttl %d)", remainingTTL)}, nil
			}

			logger.WithField("next_resolver", r.next).Debug("not in cache: go to next resolver")
			response, err = r.next.Resolve(request)

			if err == nil {
				var maxTTL uint32

				for _, a := range response.Res.Answer {
					// if TTL < mitTTL -> adjust the value, set minTTL
					if a.Header().Ttl < minTTL {
						logger.WithFields(log.Fields{
							"TTL":     a.Header().Ttl,
							"min_TTL": minTTL,
						}).Debugf("ttl is < than min TTL, using min value")

						a.Header().Ttl = minTTL
					}

					if maxTTL < a.Header().Ttl {
						maxTTL = a.Header().Ttl
					}
				}

				// put value into cache
				r.getCache(question.Qtype).Set(domain, response.Res.Answer, time.Duration(maxTTL)*time.Second)
			}
		} else {
			logger.Debugf("not A/AAAA: go to next %s", r.next)
			return r.next.Resolve(request)
		}
	}

	return response, err
}

func (r CachingResolver) String() string {
	return fmt.Sprintf("caching resolver")
}
