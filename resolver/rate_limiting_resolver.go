package resolver

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
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

	store  *bucketStore
	clock  func() time.Time
	logger *logrus.Entry

	drops         *prometheus.CounterVec
	capExhausted  prometheus.Counter
	activeBuckets prometheus.GaugeFunc
}

func NewRateLimitingResolver(cfg config.RateLimit) *RateLimitingResolver {
	r := &RateLimitingResolver{
		configurable: withConfig(&cfg),
		typed:        withType("rate-limiting"),
		clock:        time.Now,
		logger:       log.PrefixedLog("rate-limiting"),
	}
	if !cfg.IsEnabled() {
		return r
	}
	r.store = newBucketStore(rate.Limit(cfg.Rate), int(cfg.Burst), rateLimitBucketCap)
	r.store.startJanitor(rateLimitJanitorInterval)

	r.drops = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blocky_rate_limit_drops_total",
			Help: "Total number of DNS queries dropped by the rate limiter, by protocol.",
		},
		[]string{"protocol"},
	)
	r.capExhausted = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "blocky_rate_limit_cap_exhausted_total",
			Help: "Total number of queries dropped because the in-memory bucket store was full.",
		},
	)
	r.activeBuckets = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "blocky_rate_limit_active_buckets",
			Help: "Number of token buckets currently held in memory.",
		},
		func() float64 { return float64(r.store.size.Load()) },
	)
	metrics.RegisterMetric(r.drops)
	metrics.RegisterMetric(r.capExhausted)
	metrics.RegisterMetric(r.activeBuckets)

	return r
}

func (r *RateLimitingResolver) Resolve(ctx context.Context, req *model.Request) (*model.Response, error) {
	if !r.IsEnabled() {
		return r.next.Resolve(ctx, req)
	}
	ip := req.ClientIP
	if ip == nil || r.isAllowlisted(ip) {
		return r.next.Resolve(ctx, req)
	}
	key := bucketKey(ip, r.cfg.IPv4Prefix, r.cfg.IPv6Prefix)
	entry, allowed := r.store.allowAt(key, r.clock())
	if allowed {
		return r.next.Resolve(ctx, req)
	}
	if entry == nil {
		r.capExhausted.Inc()
	}
	r.recordDrop(req, entry)

	return nil, ErrRateLimited
}

func (r *RateLimitingResolver) isAllowlisted(ip net.IP) bool {
	for _, n := range r.cfg.ParsedAllowlist() {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

func (r *RateLimitingResolver) recordDrop(req *model.Request, e *bucketEntry) {
	r.drops.WithLabelValues(req.Protocol.String()).Inc()
	if e == nil {
		return
	}
	now := r.clock().UnixNano()
	prev := e.lastLogged.Load()
	if now-prev < int64(time.Second) || !e.lastLogged.CompareAndSwap(prev, now) {
		return
	}
	fields := logrus.Fields{
		"client_ip":     req.ClientIP,
		"protocol":      req.Protocol,
		"qname":         util.QuestionToString(req.Req.Question),
		"bucket_tokens": e.limiter.Tokens(),
	}
	if len(req.Req.Question) > 0 {
		fields["qtype"] = req.Req.Question[0].Qtype
	}
	r.logger.WithFields(fields).Warn("dropped query")
}
