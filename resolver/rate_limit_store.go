package resolver

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

func bucketKey(ip net.IP, v4Prefix, v6Prefix uint8) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(int(v4Prefix), 32)).String()
	}
	return ip.To16().Mask(net.CIDRMask(int(v6Prefix), 128)).String()
}

type bucketEntry struct {
	limiter    *rate.Limiter
	lastLogged atomic.Int64
}

type bucketStore struct {
	limit   rate.Limit
	burst   int
	cap     int
	buckets sync.Map
	size    atomic.Int64
}

func newBucketStore(limit rate.Limit, burst, cap int) *bucketStore {
	return &bucketStore{limit: limit, burst: burst, cap: cap}
}

// allowAt is the time-injectable Allow path used by tests and by the resolver
// (which passes r.clock()).
func (s *bucketStore) allowAt(key string, now time.Time) (*bucketEntry, bool) {
	if v, ok := s.buckets.Load(key); ok {
		e := v.(*bucketEntry)
		return e, e.limiter.AllowN(now, 1)
	}
	if s.size.Load() >= int64(s.cap) {
		return nil, false
	}
	fresh := &bucketEntry{limiter: rate.NewLimiter(s.limit, s.burst)}
	actual, loaded := s.buckets.LoadOrStore(key, fresh)
	if !loaded {
		s.size.Add(1)
	}
	e := actual.(*bucketEntry)
	return e, e.limiter.AllowN(now, 1)
}

// sweep walks the map and evicts buckets whose limiter is fully refilled
// (idle = no state worth keeping; reconstruction yields identical behavior).
func (s *bucketStore) sweep() {
	s.buckets.Range(func(k, v any) bool {
		if v.(*bucketEntry).limiter.Tokens() >= float64(s.burst) {
			s.buckets.Delete(k)
			s.size.Add(-1)
		}
		return true
	})
}
