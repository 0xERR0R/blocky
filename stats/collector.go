// Package stats provides an in-memory, bounded aggregation of DNS activity
// over a rolling 24h window. It has no dependency on resolvers or HTTP.
package stats

import (
	"sort"
	"sync"
	"time"
)

const (
	topN              = 20
	windowHours       = 24
	keepPerHour       = 2 * topN
	maxTrackedPerHour = 10_000
	hourLayout        = "2006010215"
)

// Disposition is the final outcome class of a query.
type Disposition int

const (
	DispositionAnswered Disposition = iota
	DispositionDropped
	DispositionErrored
)

// Sample is a single recorded query — primitives only; never retains *dns.Msg.
type Sample struct {
	RType       string
	Disposition Disposition
	QType       string
	RCode       string
	Domain      string
	Client      string
	Blocked     bool
	DurationMs  int64
}

// NameCount is a (name, count) pair for top-N lists.
type NameCount struct {
	Name  string
	Count int
}

// Summary holds the curated outcome categories over the window.
type Summary struct {
	Queries       int
	Cached        int
	Forwarded     int
	Blocked       int
	Local         int
	Dropped       int
	Errors        int
	AvgResponseMs int
	CacheHitRate  float64
}

// HourPoint is one point in the per-hour time series.
type HourPoint struct {
	Hour    time.Time
	Queries int
	Blocked int
}

// ListCounts holds current per-group list entry counts (point-in-time).
type ListCounts struct {
	Denylist  map[string]int
	Allowlist map[string]int
}

// Result is the full snapshot returned to the API layer.
type Result struct {
	Start             time.Time
	End               time.Time
	Summary           Summary
	ByResponseType    map[string]int
	ByQueryType       map[string]int
	ByResponseCode    map[string]int
	PerHour           []HourPoint
	TopDomains        []NameCount
	TopBlockedDomains []NameCount
	TopClients        []NameCount
	Lists             ListCounts
	CacheEntries      int
}

type bucket struct {
	hourStart      time.Time
	dropped        int
	errors         int
	durationSumMs  int64
	byResponseType map[string]int
	byQueryType    map[string]int
	byResponseCode map[string]int
	domains        map[string]int
	blockedDomains map[string]int
	clients        map[string]int
}

func newBucket(hourStart time.Time) *bucket {
	return &bucket{
		hourStart:      hourStart,
		byResponseType: map[string]int{},
		byQueryType:    map[string]int{},
		byResponseCode: map[string]int{},
		domains:        map[string]int{},
		blockedDomains: map[string]int{},
		clients:        map[string]int{},
	}
}

// Collector aggregates samples into hourly buckets with a 24h sliding window.
type Collector struct {
	mu           sync.RWMutex
	buckets      map[string]*bucket
	currentKey   string
	startTime    time.Time
	cacheEntries int
	lists        ListCounts
	now          func() time.Time
}

// NewCollector returns a Collector using the wall clock.
func NewCollector() *Collector {
	return newCollectorWithClock(time.Now)
}

func newCollectorWithClock(now func() time.Time) *Collector {
	return &Collector{
		buckets:   map[string]*bucket{},
		startTime: now(),
		lists:     ListCounts{Denylist: map[string]int{}, Allowlist: map[string]int{}},
		now:       now,
	}
}

// Record adds one sample. Safe for concurrent use.
func (c *Collector) Record(s Sample) {
	c.mu.Lock()
	defer c.mu.Unlock()

	b := c.currentBucket(c.now())
	b.durationSumMs += s.DurationMs

	if s.QType != "" {
		b.byQueryType[s.QType]++
	}

	if s.Domain != "" {
		b.domains[s.Domain]++

		if s.Blocked {
			b.blockedDomains[s.Domain]++
		}
	}

	if s.Client != "" {
		b.clients[s.Client]++
	}

	switch s.Disposition {
	case DispositionDropped:
		b.dropped++
	case DispositionErrored:
		b.errors++
	default:
		if s.RType != "" {
			b.byResponseType[s.RType]++
		}

		if s.RCode != "" {
			b.byResponseCode[s.RCode]++
		}
	}
}

// currentBucket returns the bucket for `now`, rolling over on hour change:
// it prunes the just-closed bucket, evicts buckets older than the window, and
// caps the current bucket's working set.
func (c *Collector) currentBucket(now time.Time) *bucket {
	key := now.Format(hourLayout)
	if key != c.currentKey {
		if old, ok := c.buckets[c.currentKey]; ok {
			pruneBucket(old)
		}

		c.currentKey = key
		c.evict(now)
	}

	b, ok := c.buckets[key]
	if !ok {
		b = newBucket(now.Truncate(time.Hour))
		c.buckets[key] = b
	}

	capWorkingSet(b)

	return b
}

func (c *Collector) evict(now time.Time) {
	cutoff := now.Add(-windowHours * time.Hour)
	for k, b := range c.buckets {
		if b.hourStart.Before(cutoff) {
			delete(c.buckets, k)
		}
	}
}

func pruneBucket(b *bucket) {
	b.domains = pruneMap(b.domains, keepPerHour)
	b.blockedDomains = pruneMap(b.blockedDomains, keepPerHour)
	b.clients = pruneMap(b.clients, keepPerHour)
}

func capWorkingSet(b *bucket) {
	if len(b.domains) > maxTrackedPerHour {
		b.domains = pruneMap(b.domains, keepPerHour)
	}

	if len(b.blockedDomains) > maxTrackedPerHour {
		b.blockedDomains = pruneMap(b.blockedDomains, keepPerHour)
	}

	if len(b.clients) > maxTrackedPerHour {
		b.clients = pruneMap(b.clients, keepPerHour)
	}
}

func pruneMap(m map[string]int, keep int) map[string]int {
	if len(m) <= keep {
		return m
	}

	top := topNList(m, keep)
	out := make(map[string]int, keep)

	for _, nc := range top {
		out[nc.Name] = nc.Count
	}

	return out
}

// SetCacheEntries records the current result-cache size (point-in-time).
func (c *Collector) SetCacheEntries(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cacheEntries = n
}

// SetDenylistCount records the current entry count for a denylist group.
func (c *Collector) SetDenylistCount(group string, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lists.Denylist[group] = n
}

// SetAllowlistCount records the current entry count for an allowlist group.
func (c *Collector) SetAllowlistCount(group string, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lists.Allowlist[group] = n
}

// Snapshot merges all live buckets into a Result.
func (c *Collector) Snapshot() Result {
	c.mu.RLock()
	defer c.mu.RUnlock()

	res := Result{
		ByResponseType: map[string]int{},
		ByQueryType:    map[string]int{},
		ByResponseCode: map[string]int{},
		Lists: ListCounts{
			Denylist:  copyIntMap(c.lists.Denylist),
			Allowlist: copyIntMap(c.lists.Allowlist),
		},
		CacheEntries: c.cacheEntries,
	}

	domains := map[string]int{}
	blockedDomains := map[string]int{}
	clients := map[string]int{}

	var durationSum int64

	now := c.now()
	cutoff := now.Add(-windowHours * time.Hour)

	var oldest time.Time

	hourly := make([]*bucket, 0, len(c.buckets))

	for _, b := range c.buckets {
		if b.hourStart.Before(cutoff) {
			continue // stale; not yet evicted by a Record
		}

		addInto(res.ByResponseType, b.byResponseType)
		addInto(res.ByQueryType, b.byQueryType)
		addInto(res.ByResponseCode, b.byResponseCode)
		addInto(domains, b.domains)
		addInto(blockedDomains, b.blockedDomains)
		addInto(clients, b.clients)
		res.Summary.Dropped += b.dropped
		res.Summary.Errors += b.errors
		durationSum += b.durationSumMs
		hourly = append(hourly, b)

		if oldest.IsZero() || b.hourStart.Before(oldest) {
			oldest = b.hourStart
		}
	}

	rt := res.ByResponseType
	res.Summary.Cached = rt["CACHED"]
	res.Summary.Forwarded = rt["RESOLVED"] + rt["CONDITIONAL"]
	res.Summary.Blocked = rt["BLOCKED"] + rt["FILTERED"] + rt["NOTFQDN"]
	res.Summary.Local = rt["CUSTOMDNS"] + rt["HOSTSFILE"] + rt["SPECIAL"] + rt["SYNTHESIZED"]
	res.Summary.Queries = res.Summary.Cached + res.Summary.Forwarded + res.Summary.Blocked +
		res.Summary.Local + res.Summary.Dropped + res.Summary.Errors

	if lookups := res.Summary.Cached + res.Summary.Forwarded; lookups > 0 {
		res.Summary.CacheHitRate = float64(res.Summary.Cached) / float64(lookups)
	}

	if res.Summary.Queries > 0 {
		res.Summary.AvgResponseMs = int(durationSum / int64(res.Summary.Queries))
	}

	res.TopDomains = topNList(domains, topN)
	res.TopBlockedDomains = topNList(blockedDomains, topN)
	res.TopClients = topNList(clients, topN)

	res.PerHour = perHour(hourly)

	res.Start = c.startTime
	if oldest.After(res.Start) {
		res.Start = oldest
	}

	res.End = now

	return res
}

func addInto(dst, src map[string]int) {
	for k, v := range src {
		dst[k] += v
	}
}

func copyIntMap(src map[string]int) map[string]int {
	out := make(map[string]int, len(src))
	for k, v := range src {
		out[k] = v
	}

	return out
}

func topNList(m map[string]int, n int) []NameCount {
	cs := make([]NameCount, 0, len(m))
	for k, v := range m {
		cs = append(cs, NameCount{Name: k, Count: v})
	}

	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Count != cs[j].Count {
			return cs[i].Count > cs[j].Count
		}

		return cs[i].Name < cs[j].Name
	})

	if len(cs) > n {
		cs = cs[:n]
	}

	return cs
}

func perHour(buckets []*bucket) []HourPoint {
	points := make([]HourPoint, 0, len(buckets))
	for _, b := range buckets {
		queries := b.dropped + b.errors
		for _, v := range b.byResponseType {
			queries += v
		}

		blocked := b.byResponseType["BLOCKED"] + b.byResponseType["FILTERED"] + b.byResponseType["NOTFQDN"]
		points = append(points, HourPoint{Hour: b.hourStart, Queries: queries, Blocked: blocked})
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].Hour.Before(points[j].Hour)
	})

	return points
}
