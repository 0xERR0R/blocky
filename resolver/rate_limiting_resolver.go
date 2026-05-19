package resolver

import (
	"context"
	"errors"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"golang.org/x/time/rate"
)

// ErrRateLimited signals that handleReq must write no response.
var ErrRateLimited = errors.New("client rate-limited")

const (
	// rateLimitBucketCap bounds the in-memory bucket store; hardcoded for v1.
	rateLimitBucketCap = 16384

	// rateLimitJanitorInterval is how often idle buckets are reclaimed.
	rateLimitJanitorInterval = time.Minute
)

type RateLimitingResolver struct {
	configurable[*config.RateLimit]
	NextResolver
	typed

	store *bucketStore
	clock func() time.Time
}

func NewRateLimitingResolver(cfg config.RateLimit) *RateLimitingResolver {
	r := &RateLimitingResolver{
		configurable: withConfig(&cfg),
		typed:        withType("rate-limiting"),
		clock:        time.Now,
	}
	if cfg.IsEnabled() {
		r.store = newBucketStore(rate.Limit(cfg.Rate), int(cfg.Burst), rateLimitBucketCap)
		r.store.startJanitor(rateLimitJanitorInterval)
	}
	return r
}

func (r *RateLimitingResolver) Resolve(ctx context.Context, req *model.Request) (*model.Response, error) {
	if !r.IsEnabled() {
		return r.next.Resolve(ctx, req)
	}
	return r.next.Resolve(ctx, req) // bucket logic added in later tasks
}
