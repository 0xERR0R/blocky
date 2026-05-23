package resolver

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const (
	ipv4Bits = 32
	ipv6Bits = 128
)

func bucketKey(ip net.IP, v4Prefix, v6Prefix uint8) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(int(v4Prefix), ipv4Bits)).String()
	}

	return ip.To16().Mask(net.CIDRMask(int(v6Prefix), ipv6Bits)).String()
}

type bucketEntry struct {
	limiter    *rate.Limiter
	lastLogged atomic.Int64
}

// bucketSyncMap is a type-safe wrapper around sync.Map for *bucketEntry values.
type bucketSyncMap struct{ m sync.Map }

func (m *bucketSyncMap) Load(key string) (*bucketEntry, bool) {
	v, ok := m.m.Load(key)
	if !ok {
		return nil, false
	}

	return v.(*bucketEntry), true //nolint:forcetypeassert // only *bucketEntry is ever stored
}

func (m *bucketSyncMap) LoadOrStore(key string, val *bucketEntry) (*bucketEntry, bool) {
	actual, loaded := m.m.LoadOrStore(key, val)

	return actual.(*bucketEntry), loaded //nolint:forcetypeassert // only *bucketEntry is ever stored
}

func (m *bucketSyncMap) Delete(key string) { m.m.Delete(key) }

func (m *bucketSyncMap) Range(f func(key string, val *bucketEntry) bool) {
	m.m.Range(func(k, v any) bool {
		return f(k.(string), v.(*bucketEntry)) //nolint:forcetypeassert // only string keys and *bucketEntry values are stored
	})
}

type bucketStore struct {
	limit       rate.Limit
	burst       int
	maxBuckets  int
	buckets     bucketSyncMap
	size        atomic.Int64
	janitorDone chan struct{} // closed when the janitor goroutine exits; nil until startJanitor is called
}

func newBucketStore(limit rate.Limit, burst, maxBuckets int) *bucketStore {
	return &bucketStore{limit: limit, burst: burst, maxBuckets: maxBuckets}
}

// allowAt is the time-injectable Allow path used by tests and by the resolver
// (which passes r.clock()). Returns (nil, false) when the store is full —
// callers can distinguish cap exhaustion from a rate-limit drop by checking
// the entry for nil.
func (s *bucketStore) allowAt(key string, now time.Time) (*bucketEntry, bool) {
	if e, ok := s.buckets.Load(key); ok {
		return e, e.limiter.AllowN(now, 1)
	}
	// Reserve a slot atomically before inserting so a concurrent burst of
	// fresh keys cannot push size past maxBuckets. Roll back the reservation
	// if another goroutine wins the LoadOrStore race for the same key.
	for {
		cur := s.size.Load()
		if cur >= int64(s.maxBuckets) {
			return nil, false
		}
		if s.size.CompareAndSwap(cur, cur+1) {
			break
		}
	}
	fresh := &bucketEntry{limiter: rate.NewLimiter(s.limit, s.burst)}
	e, loaded := s.buckets.LoadOrStore(key, fresh)
	if loaded {
		s.size.Add(-1)
	}

	return e, e.limiter.AllowN(now, 1)
}

// sweep walks the map and evicts buckets whose limiter is fully refilled
// (idle = no state worth keeping; reconstruction yields identical behavior).
func (s *bucketStore) sweep() {
	s.buckets.Range(func(key string, e *bucketEntry) bool {
		if e.limiter.Tokens() >= float64(s.burst) {
			s.buckets.Delete(key)
			s.size.Add(-1)
		}

		return true
	})
}

// startJanitor launches a background sweep loop that exits when ctx is done.
// The returned-via-field janitorDone channel is closed when the goroutine exits,
// giving tests a deterministic signal without polling runtime.NumGoroutine.
func (s *bucketStore) startJanitor(ctx context.Context, interval time.Duration) {
	s.janitorDone = make(chan struct{})
	go func() {
		defer close(s.janitorDone)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sweep()
			}
		}
	}()
}
