package statscollector

import (
	"maps"
	"sort"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	BucketCount       = 144 // 24h / 10min
	BucketDuration    = 10 * time.Minute
	DefaultTopN       = 10
	DefaultMaxCounter = 10000
)

// QueryRecord is the data captured per DNS query.
type QueryRecord struct {
	Timestamp    time.Time
	Client       string // client name or IP
	Domain       string // question domain (lowercase, no trailing dot)
	QueryType    string // A, AAAA, SRV, MX, etc.
	ResponseType string // RESOLVED, CACHED, BLOCKED, CUSTOMDNS, etc.

	// Upstream is true when the query was resolved by an upstream resolver,
	// in which case Latency carries the resolution duration.
	Upstream bool
	Latency  time.Duration
}

// TimeBucket holds aggregated counts for one 10-minute window.
type TimeBucket struct {
	Timestamp    time.Time      `json:"ts"`
	Total        int            `json:"total"`
	Blocked      int            `json:"blocked"`
	ClientCounts map[string]int `json:"clients,omitempty"`

	// Upstream latency accumulation. LatencySum and UpstreamCount are internal;
	// AvgLatencyMs is the per-bucket average exposed to API consumers.
	LatencySum    time.Duration `json:"-"`
	UpstreamCount int           `json:"-"`
	AvgLatencyMs  float64       `json:"avg_latency_ms"`
}

// DomainCount is a domain name with its hit count.
type DomainCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// ClientCount is a client identifier with its query count.
type ClientCount struct {
	Client string `json:"client"`
	Count  int    `json:"count"`
}

// Store is the persistence interface for stats data.
type Store interface {
	SaveStats(snap *StatsSnapshot) error
	LoadStats() (*StatsSnapshot, error)
	PruneStatsBefore(t time.Time) error
}

// StatsSnapshot is the full in-memory state for persistence.
type StatsSnapshot struct {
	Buckets  []BucketSnapshot
	Counters map[string]map[string]int // category -> key -> count
}

// BucketSnapshot is a single time bucket for persistence.
type BucketSnapshot struct {
	Timestamp     time.Time
	Total         int
	Blocked       int
	ClientCounts  map[string]int
	LatencySum    time.Duration
	UpstreamCount int
}

// Collector accumulates query stats in memory using a ring buffer.
type Collector struct {
	mu      sync.RWMutex
	buckets [BucketCount]TimeBucket
	head    int // index of current bucket

	// Running counters (since startup)
	domainPermitted map[string]int
	domainBlocked   map[string]int
	clientTotal     map[string]int
	clientBlocked   map[string]int
	queryTypes      map[string]int
	responseTypes   map[string]int

	dirty          bool // set on Record(), cleared after snapshot
	flushCount     int  // counts flushes for periodic counter pruning
	maxCounterKeys int

	// Allow injecting time for testing
	now func() time.Time

	// Persistence
	store  Store
	stopCh chan struct{}
	done   chan struct{}
}

// Option configures a Collector.
type Option func(*Collector)

// WithClock overrides the time source (useful for testing).
func WithClock(fn func() time.Time) Option {
	return func(c *Collector) { c.now = fn }
}

// WithStore enables SQLite persistence with batched flushing.
func WithStore(s Store) Option {
	return func(c *Collector) { c.store = s }
}

// WithMaxCounterKeys sets the cap for each counter map (default 10,000).
func WithMaxCounterKeys(n int) Option {
	return func(c *Collector) { c.maxCounterKeys = n }
}

// New creates a Collector ready to receive query records.
// If a Store is provided, it loads persisted state and starts a background flush goroutine.
func New(opts ...Option) *Collector {
	c := &Collector{
		domainPermitted: make(map[string]int),
		domainBlocked:   make(map[string]int),
		clientTotal:     make(map[string]int),
		clientBlocked:   make(map[string]int),
		queryTypes:      make(map[string]int),
		responseTypes:   make(map[string]int),
		maxCounterKeys:  DefaultMaxCounter,
		now:             time.Now,
		stopCh:          make(chan struct{}),
		done:            make(chan struct{}),
	}

	for _, o := range opts {
		o(c)
	}

	now := c.now().Truncate(BucketDuration)
	c.buckets[0] = TimeBucket{
		Timestamp:    now,
		ClientCounts: make(map[string]int),
	}

	if c.store != nil {
		c.loadFromStore()
		go c.flushLoop()
	} else {
		close(c.done)
	}

	return c
}

// Close stops the background flush loop and performs a final flush.
func (c *Collector) Close() {
	if c.store == nil {
		return
	}

	close(c.stopCh)
	<-c.done

	if err := c.flush(); err != nil {
		log.WithError(err).Error("Final stats flush failed")
	}
}

const flushInterval = 30 * time.Second

func (c *Collector) flushLoop() {
	defer close(c.done)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			if err := c.flush(); err != nil {
				log.WithError(err).Warn("Stats flush failed")
			}
		}
	}
}

func (c *Collector) flush() error {
	c.mu.RLock()
	dirty := c.dirty
	c.mu.RUnlock()

	if !dirty {
		return nil
	}

	snap := c.snapshot()

	if err := c.store.SaveStats(snap); err != nil {
		return err
	}

	// Prune counters every 6th flush (~3 minutes at 30s interval)
	c.flushCount++
	if c.flushCount%6 == 0 {
		c.pruneCounters()
	}

	// Prune buckets older than 24h
	cutoff := c.now().Add(-BucketCount * BucketDuration)

	return c.store.PruneStatsBefore(cutoff)
}

// snapshot captures the current state for persistence and clears dirty.
func (c *Collector) snapshot() *StatsSnapshot {
	c.mu.Lock()
	c.dirty = false
	c.mu.Unlock()

	c.mu.RLock()
	defer c.mu.RUnlock()

	snap := &StatsSnapshot{
		Counters: map[string]map[string]int{
			"domain_permitted": copyMap(c.domainPermitted),
			"domain_blocked":   copyMap(c.domainBlocked),
			"client_total":     copyMap(c.clientTotal),
			"client_blocked":   copyMap(c.clientBlocked),
			"query_type":       copyMap(c.queryTypes),
			"response_type":    copyMap(c.responseTypes),
		},
	}

	for i := range BucketCount {
		b := c.buckets[i]
		if b.Total == 0 && b.Blocked == 0 {
			continue
		}

		bs := BucketSnapshot{
			Timestamp:     b.Timestamp,
			Total:         b.Total,
			Blocked:       b.Blocked,
			LatencySum:    b.LatencySum,
			UpstreamCount: b.UpstreamCount,
		}

		if b.ClientCounts != nil {
			bs.ClientCounts = make(map[string]int, len(b.ClientCounts))
			maps.Copy(bs.ClientCounts, b.ClientCounts)
		}

		snap.Buckets = append(snap.Buckets, bs)
	}

	return snap
}

func (c *Collector) loadFromStore() {
	snap, err := c.store.LoadStats()
	if err != nil {
		log.WithError(err).Warn("Failed to load persisted stats, starting fresh")

		return
	}

	if snap == nil {
		return
	}

	now := c.now().Truncate(BucketDuration)
	cutoff := now.Add(-BucketCount * BucketDuration)

	// Restore buckets into the ring buffer
	for _, bs := range snap.Buckets {
		ts := bs.Timestamp.Truncate(BucketDuration)
		if ts.Before(cutoff) {
			continue // too old
		}

		// Ring index relative to head. This assumes c.head == 0,
		// which is guaranteed because loadFromStore runs only from New().
		offset := int(now.Sub(ts) / BucketDuration)
		if offset < 0 || offset >= BucketCount {
			continue
		}

		idx := (c.head - offset + BucketCount) % BucketCount
		c.buckets[idx] = TimeBucket{
			Timestamp:     ts,
			Total:         bs.Total,
			Blocked:       bs.Blocked,
			ClientCounts:  bs.ClientCounts,
			LatencySum:    bs.LatencySum,
			UpstreamCount: bs.UpstreamCount,
		}

		if c.buckets[idx].ClientCounts == nil {
			c.buckets[idx].ClientCounts = make(map[string]int)
		}
	}

	// Restore running counters
	if m, ok := snap.Counters["domain_permitted"]; ok {
		c.domainPermitted = m
	}
	if m, ok := snap.Counters["domain_blocked"]; ok {
		c.domainBlocked = m
	}
	if m, ok := snap.Counters["client_total"]; ok {
		c.clientTotal = m
	}
	if m, ok := snap.Counters["client_blocked"]; ok {
		c.clientBlocked = m
	}
	if m, ok := snap.Counters["query_type"]; ok {
		c.queryTypes = m
	}
	if m, ok := snap.Counters["response_type"]; ok {
		c.responseTypes = m
	}

	total := 0
	for _, v := range c.clientTotal {
		total += v
	}
	log.Infof("Restored %d persisted stats counters and %d time buckets", total, len(snap.Buckets))
}

// Record ingests a single query observation.
func (c *Collector) Record(q QueryRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.advanceBuckets()

	b := &c.buckets[c.head]
	b.Total++

	if q.ResponseType == "BLOCKED" {
		b.Blocked++
	}

	if b.ClientCounts == nil {
		b.ClientCounts = make(map[string]int)
	}

	b.ClientCounts[q.Client]++

	if q.Upstream {
		b.LatencySum += q.Latency
		b.UpstreamCount++
	}

	if q.ResponseType == "BLOCKED" {
		c.domainBlocked[q.Domain]++
		c.clientBlocked[q.Client]++
	} else {
		c.domainPermitted[q.Domain]++
	}

	c.clientTotal[q.Client]++
	c.queryTypes[q.QueryType]++
	c.responseTypes[q.ResponseType]++
	c.dirty = true
}

// pruneCounters caps each counter map to maxCounterKeys, keeping top-N by count.
func (c *Collector) pruneCounters() {
	c.mu.Lock()
	defer c.mu.Unlock()

	maps := []*map[string]int{
		&c.domainPermitted,
		&c.domainBlocked,
		&c.clientTotal,
		&c.clientBlocked,
		&c.queryTypes,
		&c.responseTypes,
	}

	for _, mp := range maps {
		m := *mp
		if len(m) <= c.maxCounterKeys {
			continue
		}

		type kv struct {
			key string
			val int
		}

		items := make([]kv, 0, len(m))
		for k, v := range m {
			items = append(items, kv{k, v})
		}

		sort.Slice(items, func(i, j int) bool {
			return items[i].val > items[j].val
		})

		pruned := make(map[string]int, c.maxCounterKeys)
		for _, item := range items[:c.maxCounterKeys] {
			pruned[item.key] = item.val
		}

		*mp = pruned
	}
}

// advanceBuckets moves the ring head forward to cover the current time window.
// Caller must hold c.mu.
func (c *Collector) advanceBuckets() {
	now := c.now().Truncate(BucketDuration)

	for c.buckets[c.head].Timestamp.Before(now) {
		prev := c.buckets[c.head].Timestamp
		c.head = (c.head + 1) % BucketCount

		c.buckets[c.head] = TimeBucket{
			Timestamp:    prev.Add(BucketDuration),
			ClientCounts: make(map[string]int),
		}

		if !c.buckets[c.head].Timestamp.Before(now) {
			break
		}
	}
}

// OverTime returns all 144 buckets in chronological order (oldest first).
// It advances the ring buffer first so stale buckets are cleared even when
// no new queries have been recorded.
func (c *Collector) OverTime() []TimeBucket {
	c.mu.Lock()
	c.advanceBuckets()
	c.mu.Unlock()

	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]TimeBucket, BucketCount)
	for i := range BucketCount {
		idx := (c.head + 1 + i) % BucketCount
		out[i] = c.buckets[idx]

		// Average upstream latency for the bucket, in milliseconds.
		if c.buckets[idx].UpstreamCount > 0 {
			avg := c.buckets[idx].LatencySum / time.Duration(c.buckets[idx].UpstreamCount)
			out[i].AvgLatencyMs = float64(avg) / float64(time.Millisecond)
		}

		// Deep-copy the client map
		if c.buckets[idx].ClientCounts != nil {
			m := make(map[string]int, len(c.buckets[idx].ClientCounts))
			maps.Copy(m, c.buckets[idx].ClientCounts)

			out[i].ClientCounts = m
		}
	}

	return out
}

// QueryTypes returns a copy of the query type distribution.
func (c *Collector) QueryTypes() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return copyMap(c.queryTypes)
}

// ResponseTypes returns a copy of the response type distribution.
func (c *Collector) ResponseTypes() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return copyMap(c.responseTypes)
}

// TopDomains returns the top-N permitted and blocked domains by hit count.
func (c *Collector) TopDomains(n int) (permitted, blocked []DomainCount) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	permitted = topN(c.domainPermitted, n, func(k string, v int) DomainCount {
		return DomainCount{Domain: k, Count: v}
	})

	blocked = topN(c.domainBlocked, n, func(k string, v int) DomainCount {
		return DomainCount{Domain: k, Count: v}
	})

	return permitted, blocked
}

// TopClients returns the top-N clients by total and blocked query count.
func (c *Collector) TopClients(n int) (total, blocked []ClientCount) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total = topN(c.clientTotal, n, func(k string, v int) ClientCount {
		return ClientCount{Client: k, Count: v}
	})

	blocked = topN(c.clientBlocked, n, func(k string, v int) ClientCount {
		return ClientCount{Client: k, Count: v}
	})

	return total, blocked
}

// ActiveClients returns the number of unique clients seen.
func (c *Collector) ActiveClients() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.clientTotal)
}

// TotalQueries returns the cumulative total and blocked query counts.
func (c *Collector) TotalQueries() (total, blocked int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, v := range c.clientTotal {
		total += v
	}

	for _, v := range c.clientBlocked {
		blocked += v
	}

	return total, blocked
}

func copyMap(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	maps.Copy(out, m)

	return out
}

// topN extracts the top-n entries from a map, sorted descending by value.
func topN[T any](m map[string]int, n int, conv func(string, int) T) []T {
	type kv struct {
		key string
		val int
	}

	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].val > items[j].val
	})

	if n > len(items) {
		n = len(items)
	}

	out := make([]T, n)
	for i := range n {
		out[i] = conv(items[i].key, items[i].val)
	}

	return out
}
