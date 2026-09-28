package statscollector

import (
	"sync"
	"testing"
	"time"
)

func TestRecordAndTotalQueries(t *testing.T) {
	c := New()

	c.Record(QueryRecord{Client: "192.168.1.1", Domain: "example.com", QueryType: "A", ResponseType: "RESOLVED"})
	c.Record(QueryRecord{Client: "192.168.1.1", Domain: "ads.com", QueryType: "A", ResponseType: "BLOCKED"})
	c.Record(QueryRecord{Client: "192.168.1.2", Domain: "example.com", QueryType: "AAAA", ResponseType: "CACHED"})

	total, blocked := c.TotalQueries()
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}

	if blocked != 1 {
		t.Errorf("blocked = %d, want 1", blocked)
	}
}

func TestActiveClients(t *testing.T) {
	c := New()

	c.Record(QueryRecord{Client: "a", Domain: "x.com", QueryType: "A", ResponseType: "RESOLVED"})
	c.Record(QueryRecord{Client: "b", Domain: "y.com", QueryType: "A", ResponseType: "RESOLVED"})
	c.Record(QueryRecord{Client: "a", Domain: "z.com", QueryType: "A", ResponseType: "RESOLVED"})

	if got := c.ActiveClients(); got != 2 {
		t.Errorf("ActiveClients() = %d, want 2", got)
	}
}

func TestQueryAndResponseTypes(t *testing.T) {
	c := New()

	c.Record(QueryRecord{Client: "c1", Domain: "a.com", QueryType: "A", ResponseType: "RESOLVED"})
	c.Record(QueryRecord{Client: "c1", Domain: "b.com", QueryType: "A", ResponseType: "BLOCKED"})
	c.Record(QueryRecord{Client: "c1", Domain: "c.com", QueryType: "AAAA", ResponseType: "CACHED"})

	qt := c.QueryTypes()
	if qt["A"] != 2 {
		t.Errorf("QueryTypes[A] = %d, want 2", qt["A"])
	}

	if qt["AAAA"] != 1 {
		t.Errorf("QueryTypes[AAAA] = %d, want 1", qt["AAAA"])
	}

	rt := c.ResponseTypes()
	if rt["RESOLVED"] != 1 || rt["BLOCKED"] != 1 || rt["CACHED"] != 1 {
		t.Errorf("unexpected ResponseTypes: %v", rt)
	}
}

func TestTopDomains(t *testing.T) {
	c := New()

	// 3 permitted hits for example.com, 2 for google.com, 1 for other.com
	for range 3 {
		c.Record(QueryRecord{Client: "c", Domain: "example.com", QueryType: "A", ResponseType: "RESOLVED"})
	}

	for range 2 {
		c.Record(QueryRecord{Client: "c", Domain: "google.com", QueryType: "A", ResponseType: "RESOLVED"})
	}

	c.Record(QueryRecord{Client: "c", Domain: "other.com", QueryType: "A", ResponseType: "RESOLVED"})

	// 2 blocked hits for ads.com, 1 for tracker.com
	for range 2 {
		c.Record(QueryRecord{Client: "c", Domain: "ads.com", QueryType: "A", ResponseType: "BLOCKED"})
	}

	c.Record(QueryRecord{Client: "c", Domain: "tracker.com", QueryType: "A", ResponseType: "BLOCKED"})

	permitted, blocked := c.TopDomains(2)

	if len(permitted) != 2 {
		t.Fatalf("len(permitted) = %d, want 2", len(permitted))
	}

	if permitted[0].Domain != "example.com" || permitted[0].Count != 3 {
		t.Errorf("permitted[0] = %v, want {example.com, 3}", permitted[0])
	}

	if permitted[1].Domain != "google.com" || permitted[1].Count != 2 {
		t.Errorf("permitted[1] = %v, want {google.com, 2}", permitted[1])
	}

	if len(blocked) != 2 {
		t.Fatalf("len(blocked) = %d, want 2", len(blocked))
	}

	if blocked[0].Domain != "ads.com" || blocked[0].Count != 2 {
		t.Errorf("blocked[0] = %v, want {ads.com, 2}", blocked[0])
	}
}

func TestTopClients(t *testing.T) {
	c := New()

	for range 5 {
		c.Record(QueryRecord{Client: "heavy", Domain: "x.com", QueryType: "A", ResponseType: "RESOLVED"})
	}

	for range 2 {
		c.Record(QueryRecord{Client: "light", Domain: "x.com", QueryType: "A", ResponseType: "BLOCKED"})
	}

	total, blocked := c.TopClients(10)

	if len(total) != 2 {
		t.Fatalf("len(total) = %d, want 2", len(total))
	}

	if total[0].Client != "heavy" || total[0].Count != 5 {
		t.Errorf("total[0] = %v, want {heavy, 5}", total[0])
	}

	if len(blocked) != 1 {
		t.Fatalf("len(blocked) = %d, want 1", len(blocked))
	}

	if blocked[0].Client != "light" || blocked[0].Count != 2 {
		t.Errorf("blocked[0] = %v, want {light, 2}", blocked[0])
	}
}

func TestBucketAdvancement(t *testing.T) {
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := baseTime

	c := New(WithClock(func() time.Time { return now }))

	// Record in first bucket
	c.Record(QueryRecord{Client: "c1", Domain: "a.com", QueryType: "A", ResponseType: "RESOLVED"})

	// Advance 10 minutes
	now = baseTime.Add(10 * time.Minute)
	c.Record(QueryRecord{Client: "c1", Domain: "b.com", QueryType: "A", ResponseType: "BLOCKED"})

	// Advance another 10 minutes
	now = baseTime.Add(20 * time.Minute)
	c.Record(QueryRecord{Client: "c1", Domain: "c.com", QueryType: "A", ResponseType: "RESOLVED"})

	buckets := c.OverTime()

	// Find non-zero buckets
	var nonZero []TimeBucket
	for _, b := range buckets {
		if b.Total > 0 {
			nonZero = append(nonZero, b)
		}
	}

	if len(nonZero) != 3 {
		t.Fatalf("non-zero buckets = %d, want 3", len(nonZero))
	}

	if nonZero[0].Total != 1 || nonZero[0].Blocked != 0 {
		t.Errorf("bucket[0] total=%d blocked=%d, want 1/0", nonZero[0].Total, nonZero[0].Blocked)
	}

	if nonZero[1].Total != 1 || nonZero[1].Blocked != 1 {
		t.Errorf("bucket[1] total=%d blocked=%d, want 1/1", nonZero[1].Total, nonZero[1].Blocked)
	}

	if nonZero[2].Total != 1 || nonZero[2].Blocked != 0 {
		t.Errorf("bucket[2] total=%d blocked=%d, want 1/0", nonZero[2].Total, nonZero[2].Blocked)
	}
}

func TestUpstreamLatencyAverage(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := New(WithClock(func() time.Time { return now }))

	// Two upstream queries (20ms + 40ms) average to 30ms.
	c.Record(QueryRecord{Client: "c", Domain: "a.com", QueryType: "A", ResponseType: "RESOLVED", Upstream: true, Latency: 20 * time.Millisecond})
	c.Record(QueryRecord{Client: "c", Domain: "b.com", QueryType: "A", ResponseType: "RESOLVED", Upstream: true, Latency: 40 * time.Millisecond})
	// Non-upstream queries must not affect the average.
	c.Record(QueryRecord{Client: "c", Domain: "ads.com", QueryType: "A", ResponseType: "BLOCKED", Upstream: false, Latency: 5 * time.Second})
	c.Record(QueryRecord{Client: "c", Domain: "cached.com", QueryType: "A", ResponseType: "CACHED", Upstream: false})

	var got float64
	for _, b := range c.OverTime() {
		if b.UpstreamCount > 0 {
			got = b.AvgLatencyMs
		}
	}

	if got != 30 {
		t.Errorf("avg latency = %.1fms, want 30ms", got)
	}
}

func TestUpstreamLatencyEmptyBucket(t *testing.T) {
	c := New()
	c.Record(QueryRecord{Client: "c", Domain: "ads.com", QueryType: "A", ResponseType: "BLOCKED", Upstream: false})

	for _, b := range c.OverTime() {
		if b.AvgLatencyMs != 0 {
			t.Errorf("avg latency = %.1f, want 0 when no upstream queries", b.AvgLatencyMs)
		}
	}
}

func TestBucketWraparound(t *testing.T) {
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := baseTime

	c := New(WithClock(func() time.Time { return now }))

	c.Record(QueryRecord{Client: "c", Domain: "old.com", QueryType: "A", ResponseType: "RESOLVED"})

	// Jump 25 hours — more than 144 buckets — old data should be overwritten
	now = baseTime.Add(25 * time.Hour)
	c.Record(QueryRecord{Client: "c", Domain: "new.com", QueryType: "A", ResponseType: "RESOLVED"})

	buckets := c.OverTime()
	totalNonZero := 0

	for _, b := range buckets {
		if b.Total > 0 {
			totalNonZero++
		}
	}

	// Only the latest bucket should have data (old one was overwritten)
	if totalNonZero != 1 {
		t.Errorf("non-zero buckets = %d, want 1 (old data should be gone)", totalNonZero)
	}
}

func TestOverTimeChronological(t *testing.T) {
	c := New()
	buckets := c.OverTime()

	if len(buckets) != BucketCount {
		t.Fatalf("len(buckets) = %d, want %d", len(buckets), BucketCount)
	}

	// Verify chronological order among non-zero timestamps
	var prev time.Time
	for _, b := range buckets {
		if b.Timestamp.IsZero() {
			continue
		}

		if !prev.IsZero() && b.Timestamp.Before(prev) {
			t.Errorf("bucket timestamps not chronological: %v before %v", b.Timestamp, prev)
		}

		prev = b.Timestamp
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New()

	var wg sync.WaitGroup

	// 10 goroutines writing
	for range 10 {
		wg.Go(func() {
			for range 100 {
				c.Record(QueryRecord{
					Client:       "client",
					Domain:       "example.com",
					QueryType:    "A",
					ResponseType: "RESOLVED",
				})
			}
		})
	}

	// 5 goroutines reading
	for range 5 {
		wg.Go(func() {
			for range 50 {
				_ = c.OverTime()
				_ = c.QueryTypes()
				_ = c.ResponseTypes()
				c.TopDomains(5)
				c.TopClients(5)
				c.TotalQueries()
				c.ActiveClients()
			}
		})
	}

	wg.Wait()

	total, _ := c.TotalQueries()
	if total != 1000 {
		t.Errorf("total = %d, want 1000", total)
	}
}

func TestTopNLargerThanData(t *testing.T) {
	c := New()

	c.Record(QueryRecord{Client: "c", Domain: "only.com", QueryType: "A", ResponseType: "RESOLVED"})

	permitted, _ := c.TopDomains(100)
	if len(permitted) != 1 {
		t.Errorf("len(permitted) = %d, want 1", len(permitted))
	}
}

func TestOverTimeClearsStaleWithoutNewQueries(t *testing.T) {
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := baseTime

	c := New(WithClock(func() time.Time { return now }))

	// Record some traffic
	c.Record(QueryRecord{Client: "c1", Domain: "a.com", QueryType: "A", ResponseType: "RESOLVED"})
	c.Record(QueryRecord{Client: "c1", Domain: "b.com", QueryType: "A", ResponseType: "BLOCKED"})

	// Verify data is present
	buckets := c.OverTime()
	nonZero := 0
	for _, b := range buckets {
		if b.Total > 0 {
			nonZero++
		}
	}

	if nonZero != 1 {
		t.Fatalf("before gap: non-zero buckets = %d, want 1", nonZero)
	}

	// Jump forward a week with NO new queries — simulates idle server
	now = baseTime.Add(7 * 24 * time.Hour)

	// OverTime should return all-zero buckets (stale data cleared)
	buckets = c.OverTime()
	nonZero = 0
	for _, b := range buckets {
		if b.Total > 0 {
			nonZero++
		}
	}

	if nonZero != 0 {
		t.Errorf("after 1-week gap with no queries: non-zero buckets = %d, want 0", nonZero)
	}
}

func TestClientCountsInBuckets(t *testing.T) {
	c := New()

	c.Record(QueryRecord{Client: "alice", Domain: "x.com", QueryType: "A", ResponseType: "RESOLVED"})
	c.Record(QueryRecord{Client: "alice", Domain: "y.com", QueryType: "A", ResponseType: "RESOLVED"})
	c.Record(QueryRecord{Client: "bob", Domain: "x.com", QueryType: "A", ResponseType: "RESOLVED"})

	buckets := c.OverTime()

	// Find the bucket with data (last one)
	last := buckets[len(buckets)-1]
	if last.ClientCounts["alice"] != 2 {
		t.Errorf("alice count = %d, want 2", last.ClientCounts["alice"])
	}

	if last.ClientCounts["bob"] != 1 {
		t.Errorf("bob count = %d, want 1", last.ClientCounts["bob"])
	}
}
