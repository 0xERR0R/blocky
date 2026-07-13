// Package stats provides an in-memory, bounded aggregation of DNS activity
// over a rolling 24h window. It has no dependency on resolvers or HTTP.
package stats

import (
	"maps"
	"sort"
	"sync"
	"time"

	"github.com/0xERR0R/blocky/model"
)

const (
	topN = 20
	// keepPerHour caps the per-hour working set retained for top-N lists once a
	// bucket is closed. It is generous headroom over topN because the window-wide
	// top-N is approximate: a name that never ranks in an hour's top keepPerHour
	// is dropped from that bucket, so under very high cardinality the 24h lists
	// can miss a name whose total would otherwise place it in the top topN.
	keepPerHour       = 10 * topN
	windowHours       = 24
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
// Whether the query was blocked is derived from RType (see isBlockedRType), so
// there is a single source of truth for the "blocked" classification.
type Sample struct {
	RType       string
	Disposition Disposition
	QType       string
	RCode       string
	Domain      string
	Client      string
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
	Filtered      int
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
		buckets: map[string]*bucket{},
		// Normalize to UTC so every timestamp the API reports (start/end/perHour)
		// is in a single zone, consistent with the UTC-keyed buckets.
		startTime: now().UTC(),
		lists:     ListCounts{Denylist: map[string]int{}, Allowlist: map[string]int{}},
		now:       now,
	}
}

// Record adds one sample. Safe for concurrent use.
func (c *Collector) Record(s Sample) {
	c.mu.Lock()
	defer c.mu.Unlock()

	b := c.currentBucket(c.now())

	// Only answered queries contribute to the response-time average; drops and
	// errors have no meaningful "response" latency.
	if s.Disposition == DispositionAnswered {
		b.durationSumMs += s.DurationMs
	}

	if s.QType != "" {
		b.byQueryType[s.QType]++
	}

	if s.Domain != "" {
		b.domains[s.Domain]++

		if isBlockedRType(s.RType) {
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
	case DispositionAnswered:
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
	// Key and hourStart both derive from the absolute, UTC-normalized truncated
	// hour, so they can never disagree and every reported timestamp stays in UTC.
	// Formatting the local wall-clock instead would collide across a DST
	// fall-back (two physical hours share one key, skipping rollover) and
	// mislabel buckets in sub-hour-offset zones.
	hourStart := now.Truncate(time.Hour).UTC()
	key := hourStart.Format(hourLayout)

	if key != c.currentKey {
		if old, ok := c.buckets[c.currentKey]; ok {
			pruneBucket(old)
		}

		c.currentKey = key
		c.evict(now)
	}

	b, ok := c.buckets[key]
	if !ok {
		b = newBucket(hourStart)
		c.buckets[key] = b
	}

	capWorkingSet(b)

	return b
}

func (c *Collector) evict(now time.Time) {
	cutoff := now.Add(-windowHours * time.Hour)
	for k, b := range c.buckets {
		// Keep only buckets whose hour starts strictly within the window, so the
		// oldest retained data is never older than windowHours.
		if !b.hourStart.After(cutoff) {
			delete(c.buckets, k)
		}
	}
}

// trackedMaps returns the high-cardinality maps that are bounded by pruning, so
// pruneBucket and capWorkingSet stay in sync when a dimension is added.
func (b *bucket) trackedMaps() []*map[string]int {
	return []*map[string]int{&b.domains, &b.blockedDomains, &b.clients}
}

func pruneBucket(b *bucket) {
	for _, m := range b.trackedMaps() {
		*m = pruneMap(*m)
	}
}

func capWorkingSet(b *bucket) {
	for _, m := range b.trackedMaps() {
		if len(*m) > maxTrackedPerHour {
			*m = pruneMap(*m)
		}
	}
}

// pruneMap keeps only the keepPerHour highest-count entries of m.
func pruneMap(m map[string]int) map[string]int {
	if len(m) <= keepPerHour {
		return m
	}

	top := topNList(m, keepPerHour)
	out := make(map[string]int, keepPerHour)

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

// liveAggregate is the merge of all in-window buckets, computed under the lock.
type liveAggregate struct {
	byResponseType, byQueryType, byResponseCode map[string]int
	domains, blockedDomains, clients            map[string]int
	hourly                                      []*bucket
	durationSum                                 int64
	dropped, errs                               int
	oldest                                      time.Time
}

// mergeLiveBuckets aggregates all buckets within the window. Caller holds the lock.
func (c *Collector) mergeLiveBuckets(now time.Time) liveAggregate {
	agg := liveAggregate{
		byResponseType: map[string]int{},
		byQueryType:    map[string]int{},
		byResponseCode: map[string]int{},
		domains:        map[string]int{},
		blockedDomains: map[string]int{},
		clients:        map[string]int{},
		hourly:         make([]*bucket, 0, len(c.buckets)),
	}

	cutoff := now.Add(-windowHours * time.Hour)

	for _, b := range c.buckets {
		if !b.hourStart.After(cutoff) {
			continue // stale; not yet evicted by a Record
		}

		addInto(agg.byResponseType, b.byResponseType)
		addInto(agg.byQueryType, b.byQueryType)
		addInto(agg.byResponseCode, b.byResponseCode)
		addInto(agg.domains, b.domains)
		addInto(agg.blockedDomains, b.blockedDomains)
		addInto(agg.clients, b.clients)
		agg.dropped += b.dropped
		agg.errs += b.errors
		agg.durationSum += b.durationSumMs
		agg.hourly = append(agg.hourly, b)

		if agg.oldest.IsZero() || b.hourStart.Before(agg.oldest) {
			agg.oldest = b.hourStart
		}
	}

	return agg
}

// Snapshot merges all live buckets into a Result.
func (c *Collector) Snapshot() Result {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := c.now().UTC()
	agg := c.mergeLiveBuckets(now)

	res := Result{
		Summary:           curatedSummary(agg.byResponseType, agg.dropped, agg.errs, agg.durationSum),
		ByResponseType:    agg.byResponseType,
		ByQueryType:       agg.byQueryType,
		ByResponseCode:    agg.byResponseCode,
		PerHour:           perHour(agg.hourly),
		TopDomains:        topNList(agg.domains, topN),
		TopBlockedDomains: topNList(agg.blockedDomains, topN),
		TopClients:        topNList(agg.clients, topN),
		Lists: ListCounts{
			Denylist:  copyIntMap(c.lists.Denylist),
			Allowlist: copyIntMap(c.lists.Allowlist),
		},
		CacheEntries: c.cacheEntries,
		Start:        c.startTime,
		End:          now,
	}

	if agg.oldest.After(res.Start) {
		res.Start = agg.oldest
	}

	return res
}

// responseCategory is the curated outcome bucket a model.ResponseType maps to.
type responseCategory int

const (
	categoryOther responseCategory = iota
	categoryCached
	categoryForwarded
	categoryBlocked
	categoryFiltered
	categoryLocal
)

// categorize is the single source of truth that maps a model.ResponseType string
// to its curated outcome category. Referencing the model constants (rather than
// bare string literals) keeps this in lockstep with the enum at compile time.
func categorize(rtype string) responseCategory {
	switch rtype {
	case model.ResponseTypeCACHED.String():
		return categoryCached
	case model.ResponseTypeRESOLVED.String(), model.ResponseTypeCONDITIONAL.String():
		return categoryForwarded
	case model.ResponseTypeBLOCKED.String():
		return categoryBlocked
	case model.ResponseTypeFILTERED.String(), model.ResponseTypeNOTFQDN.String():
		// Query-type filtering (e.g. AAAA via filtering.queryTypes) and NOTFQDN
		// rejections are not blocklist hits, so they get their own bucket and no
		// longer inflate "blocked" or the Top Blocked table (#2151).
		return categoryFiltered
	case model.ResponseTypeCUSTOMDNS.String(), model.ResponseTypeHOSTSFILE.String(),
		model.ResponseTypeSPECIAL.String(), model.ResponseTypeSYNTHESIZED.String():
		return categoryLocal
	default:
		return categoryOther
	}
}

// isBlockedRType reports whether a response type is a true blocklist hit
// (BLOCKED). Query-type-filtered / NOTFQDN responses are deliberately excluded
// so the Top Blocked table and the per-hour blocked series count only real
// blocks (#2151).
func isBlockedRType(rtype string) bool {
	return categorize(rtype) == categoryBlocked
}

// curatedSummary maps the raw per-RType counts into blocky's outcome categories.
// Queries counts every answered response (even one whose type maps to no named
// category) plus drops and errors, so a future model.ResponseType can never
// silently vanish from the total. answeredDurationSum already excludes
// drop/error latency, so the average is over answered responses only.
func curatedSummary(rt map[string]int, dropped, errs int, answeredDurationSum int64) Summary {
	s := Summary{Dropped: dropped, Errors: errs}

	answered := 0

	for rtype, n := range rt {
		answered += n

		switch categorize(rtype) {
		case categoryCached:
			s.Cached += n
		case categoryForwarded:
			s.Forwarded += n
		case categoryBlocked:
			s.Blocked += n
		case categoryFiltered:
			s.Filtered += n
		case categoryLocal:
			s.Local += n
		case categoryOther:
		}
	}

	s.Queries = answered + dropped + errs

	if lookups := s.Cached + s.Forwarded; lookups > 0 {
		s.CacheHitRate = float64(s.Cached) / float64(lookups)
	}

	if answered > 0 {
		s.AvgResponseMs = int(answeredDurationSum / int64(answered))
	}

	return s
}

func addInto(dst, src map[string]int) {
	for k, v := range src {
		dst[k] += v
	}
}

func copyIntMap(src map[string]int) map[string]int {
	out := make(map[string]int, len(src))
	maps.Copy(out, src)

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
		blocked := 0

		for rtype, v := range b.byResponseType {
			queries += v

			if isBlockedRType(rtype) {
				blocked += v
			}
		}

		points = append(points, HourPoint{Hour: b.hourStart, Queries: queries, Blocked: blocked})
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].Hour.Before(points[j].Hour)
	})

	return points
}
