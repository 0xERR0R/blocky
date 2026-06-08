package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/lists"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/stats"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
)

// statsChannelBuffer bounds the in-flight sample queue. A full buffer drops
// samples rather than blocking DNS resolution.
const statsChannelBuffer = 1024

// busSubscription remembers a handler registered on the global event bus so it
// can be detached when the resolver is stopped.
type busSubscription struct {
	topic   string
	handler any
}

// StatsResolver collects in-memory query statistics over a 24h window and
// exposes them via the stats.Result snapshot. It sits at the top of the chain
// so it observes every query's final disposition (including drops/filtered).
type StatsResolver struct {
	configurable[*config.Statistics]
	NextResolver
	typed

	collector     *stats.Collector
	samples       chan stats.Sample
	subscriptions []busSubscription
	dropped       atomic.Uint64
}

// NewStatsResolver creates a StatsResolver. When disabled it allocates no
// collector and starts no goroutine; Resolve is a pass-through. When enabled,
// the consumer goroutine and event-bus subscriptions are released when ctx is
// cancelled.
func NewStatsResolver(ctx context.Context, cfg config.Statistics) *StatsResolver {
	r := &StatsResolver{
		configurable: withConfig(&cfg),
		typed:        withType("stats"),
	}

	if !cfg.Enable {
		return r
	}

	r.collector = stats.NewCollector()
	r.samples = make(chan stats.Sample, statsChannelBuffer)

	// Subscribe before starting the consumer so subscriptions is fully written
	// before the goroutine that reads it on shutdown begins.
	r.subscribeEvents()

	go r.consume(ctx)

	return r
}

// consume drains samples into the collector until ctx is cancelled, then
// detaches the event-bus handlers so the resolver can be garbage-collected.
func (r *StatsResolver) consume(ctx context.Context) {
	defer r.unsubscribeEvents()

	for {
		select {
		case <-ctx.Done():
			return
		case s := <-r.samples:
			r.collector.Record(s)
		}
	}
}

// subscribeEvents keeps the point-in-time list/cache gauges up to date from the
// same event bus the metrics package uses.
func (r *StatsResolver) subscribeEvents() {
	subscribe := func(topic string, fn any) {
		util.FatalOnError(fmt.Sprintf("can't subscribe topic '%s'", topic), evt.Bus().Subscribe(topic, fn))
		r.subscriptions = append(r.subscriptions, busSubscription{topic: topic, handler: fn})
	}

	subscribe(evt.CachingResultCacheChanged, func(cnt int) {
		r.collector.SetCacheEntries(cnt)
	})

	subscribe(evt.BlockingCacheGroupChanged, func(listType lists.ListCacheType, group string, cnt int) {
		switch listType {
		case lists.ListCacheTypeDenylist:
			r.collector.SetDenylistCount(group, cnt)
		case lists.ListCacheTypeAllowlist:
			r.collector.SetAllowlistCount(group, cnt)
		}
	})
}

// unsubscribeEvents detaches the gauge handlers from the global bus so a stopped
// resolver stops receiving events and does not accumulate on the shared bus.
func (r *StatsResolver) unsubscribeEvents() {
	for _, sub := range r.subscriptions {
		_ = evt.Bus().Unsubscribe(sub.topic, sub.handler)
	}
}

// StatsEnabled reports whether statistics collection is active.
func (r *StatsResolver) StatsEnabled() bool {
	return r.collector != nil
}

// Stats returns the current snapshot (empty when disabled).
func (r *StatsResolver) Stats() stats.Result {
	if r.collector == nil {
		return stats.Result{}
	}

	return r.collector.Snapshot()
}

// Resolve forwards the request and records the outcome (when enabled).
func (r *StatsResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	resp, err := r.next.Resolve(ctx, request)

	if r.collector != nil {
		r.send(ctx, buildSample(request, resp, err))
	}

	return resp, err
}

// send performs a non-blocking enqueue; a full buffer drops the sample so
// resolution is never delayed by statistics. Drops are counted and logged once
// so silent undercounting under load is observable.
func (r *StatsResolver) send(ctx context.Context, s stats.Sample) {
	select {
	case r.samples <- s:
	default:
		if r.dropped.Add(1) == 1 {
			_, logger := r.log(ctx)
			logger.Warnf("statistics sample buffer (%d) full; dropping samples, stats will undercount under load",
				statsChannelBuffer)
		}
	}
}

func buildSample(request *model.Request, resp *model.Response, err error) stats.Sample {
	s := stats.Sample{
		Client: clientID(request),
	}

	// Guard against an unset timestamp, which would otherwise produce an absurd
	// duration (time since the zero time) and poison the response-time average.
	if !request.RequestTS.IsZero() {
		s.DurationMs = time.Since(request.RequestTS).Milliseconds()
	}

	if request.Req != nil && len(request.Req.Question) > 0 {
		s.QType = dns.TypeToString[request.Req.Question[0].Qtype]
		s.Domain = util.ExtractDomain(request.Req.Question[0])
	}

	switch {
	case err != nil && errors.Is(err, ErrRateLimited):
		s.Disposition = stats.DispositionDropped
	case err != nil || resp == nil:
		s.Disposition = stats.DispositionErrored
	default:
		s.Disposition = stats.DispositionAnswered
		s.RType = resp.RType.String()

		if resp.Res != nil {
			s.RCode = dns.RcodeToString[resp.Res.Rcode]
		}
	}

	return s
}

// clientID returns the joined client names, falling back to the client IP.
func clientID(request *model.Request) string {
	if name := strings.Join(request.ClientNames, ","); name != "" {
		return name
	}

	if request.ClientIP != nil {
		return request.ClientIP.String()
	}

	return ""
}
