package resolver

import (
	"net"
	"strconv"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/time/rate"
)

var _ = Describe("bucketKey", func() {
	It("uses /32 mask for IPv4", func() {
		Expect(bucketKey(net.ParseIP("192.0.2.5"), 32, 64)).Should(Equal("192.0.2.5"))
	})

	It("aggregates IPv4 by configured prefix", func() {
		a := bucketKey(net.ParseIP("192.0.2.5"), 24, 64)
		b := bucketKey(net.ParseIP("192.0.2.99"), 24, 64)
		Expect(a).Should(Equal(b))
	})

	It("aggregates IPv6 by /64 default", func() {
		a := bucketKey(net.ParseIP("2001:db8::1"), 32, 64)
		b := bucketKey(net.ParseIP("2001:db8::ffff"), 32, 64)
		Expect(a).Should(Equal(b))
	})

	It("separates different IPv6 /64s", func() {
		a := bucketKey(net.ParseIP("2001:db8:1::1"), 32, 64)
		b := bucketKey(net.ParseIP("2001:db8:2::1"), 32, 64)
		Expect(a).ShouldNot(Equal(b))
	})

	It("normalises IPv4-mapped IPv6 to v4", func() {
		mapped := net.ParseIP("::ffff:192.0.2.5")
		v4 := net.ParseIP("192.0.2.5")
		Expect(bucketKey(mapped, 32, 64)).Should(Equal(bucketKey(v4, 32, 64)))
	})
})

var _ = Describe("bucketStore", func() {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	It("allows the first burst requests for a fresh key", func() {
		s := newBucketStore(rate.Limit(1), 3, 1024)
		for range 3 {
			_, ok := s.allowAt("k", now)
			Expect(ok).Should(BeTrue())
		}
		_, ok := s.allowAt("k", now)
		Expect(ok).Should(BeFalse())
	})

	It("refills tokens over time", func() {
		s := newBucketStore(rate.Limit(1), 1, 1024)
		_, ok := s.allowAt("k", now)
		Expect(ok).Should(BeTrue())
		_, ok = s.allowAt("k", now)
		Expect(ok).Should(BeFalse())
		_, ok = s.allowAt("k", now.Add(time.Second))
		Expect(ok).Should(BeTrue())
	})

	It("keeps separate buckets per key", func() {
		s := newBucketStore(rate.Limit(1), 1, 1024)
		_, okA := s.allowAt("a", now)
		_, okB := s.allowAt("b", now)
		Expect(okA).Should(BeTrue())
		Expect(okB).Should(BeTrue())
		Expect(s.size.Load()).Should(BeNumerically("==", 2))
	})

	It("drops new keys once cap is reached", func() {
		s := newBucketStore(rate.Limit(1), 1, 2)
		_, _ = s.allowAt("a", now)
		_, _ = s.allowAt("b", now)
		_, ok := s.allowAt("c", now)
		Expect(ok).Should(BeFalse())
		Expect(s.size.Load()).Should(BeNumerically("==", 2))
	})

	It("sweep removes fully-refilled buckets", func() {
		s := newBucketStore(rate.Limit(1), 1, 1024)
		_, _ = s.allowAt("idle", now)                // bucket created, 0 tokens left
		_, _ = s.allowAt("idle", now.Add(time.Hour)) // refills (capped at burst=1)
		s.sweep()
		Expect(s.size.Load()).Should(BeNumerically("==", 0))
	})

	It("sweep keeps partially-drained buckets", func() {
		s := newBucketStore(rate.Limit(1), 5, 1024)
		recent := time.Now()               // Use current time so bucket appears partially drained
		_, _ = s.allowAt("active", recent) // 4 tokens left, not full
		s.sweep()
		Expect(s.size.Load()).Should(BeNumerically("==", 1))
	})

	It("never exceeds cap under concurrent burst of distinct fresh keys", func() {
		const capacity = 8
		s := newBucketStore(rate.Limit(1000), 1, capacity)

		var wg sync.WaitGroup
		const N = 200
		for i := range N {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, _ = s.allowAt("k-"+strconv.Itoa(i), time.Now())
			}(i)
		}
		wg.Wait()

		Expect(s.size.Load()).Should(BeNumerically("==", capacity))
	})

	It("exactly one limiter wins under concurrent LoadOrStore for same fresh key", func() {
		s := newBucketStore(rate.Limit(1000), 1000, 1024)
		var wg sync.WaitGroup
		const N = 200
		for range N {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = s.allowAt("shared", time.Now())
			}()
		}
		wg.Wait()
		Expect(s.size.Load()).Should(BeNumerically("==", 1))
	})
})
