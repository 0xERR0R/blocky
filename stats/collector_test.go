package stats

import (
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Collector", func() {
	var sut *Collector

	BeforeEach(func() {
		sut = NewCollector()
	})

	answered := func(rtype, qtype, rcode, domain, client string, blocked bool) Sample {
		return Sample{
			Disposition: DispositionAnswered,
			RType:       rtype, QType: qtype, RCode: rcode,
			Domain: domain, Client: client, Blocked: blocked, DurationMs: 10,
		}
	}

	Describe("summary", func() {
		It("classifies response types into curated categories", func() {
			sut.Record(answered("CACHED", "A", "NOERROR", "a.com", "c1", false))
			sut.Record(answered("RESOLVED", "A", "NOERROR", "b.com", "c1", false))
			sut.Record(answered("CONDITIONAL", "A", "NOERROR", "c.com", "c2", false))
			sut.Record(answered("BLOCKED", "A", "NOERROR", "ads.com", "c2", true))
			sut.Record(answered("FILTERED", "AAAA", "NOERROR", "d.com", "c2", true))
			sut.Record(answered("HOSTSFILE", "A", "NOERROR", "e.com", "c1", false))
			sut.Record(Sample{Disposition: DispositionDropped, QType: "A", Domain: "x.com", Client: "c3", DurationMs: 1})
			sut.Record(Sample{Disposition: DispositionErrored, QType: "A", DurationMs: 2})

			res := sut.Snapshot()

			Expect(res.Summary.Cached).Should(Equal(1))
			Expect(res.Summary.Forwarded).Should(Equal(2)) // RESOLVED + CONDITIONAL
			Expect(res.Summary.Blocked).Should(Equal(2))   // BLOCKED + FILTERED
			Expect(res.Summary.Local).Should(Equal(1))     // HOSTSFILE
			Expect(res.Summary.Dropped).Should(Equal(1))
			Expect(res.Summary.Errors).Should(Equal(1))
			Expect(res.Summary.Queries).Should(Equal(8))
			Expect(res.Summary.AvgResponseMs).Should(Equal(7))
		})

		It("computes cacheHitRate as cached/(cached+forwarded)", func() {
			sut.Record(answered("CACHED", "A", "NOERROR", "a.com", "c1", false))
			sut.Record(answered("CACHED", "A", "NOERROR", "a.com", "c1", false))
			sut.Record(answered("RESOLVED", "A", "NOERROR", "b.com", "c1", false))

			Expect(sut.Snapshot().Summary.CacheHitRate).Should(BeNumerically("~", 0.666, 0.01))
		})

		It("returns zero cacheHitRate when there are no cache lookups", func() {
			sut.Record(answered("BLOCKED", "A", "NOERROR", "ads.com", "c1", true))

			Expect(sut.Snapshot().Summary.CacheHitRate).Should(Equal(0.0))
		})

		It("orders equal-count top entries alphabetically", func() {
			sut.Record(answered("RESOLVED", "A", "NOERROR", "bbb.com", "c1", false))
			sut.Record(answered("RESOLVED", "A", "NOERROR", "aaa.com", "c1", false))

			top := sut.Snapshot().TopDomains
			Expect(top).Should(HaveLen(2))
			Expect(top[0].Name).Should(Equal("aaa.com"))
			Expect(top[1].Name).Should(Equal("bbb.com"))
		})

		It("exposes raw byResponseType / byQueryType / byResponseCode", func() {
			sut.Record(answered("CACHED", "A", "NOERROR", "a.com", "c1", false))
			sut.Record(answered("BLOCKED", "AAAA", "NXDOMAIN", "ads.com", "c1", true))

			res := sut.Snapshot()
			Expect(res.ByResponseType).Should(HaveKeyWithValue("CACHED", 1))
			Expect(res.ByResponseType).Should(HaveKeyWithValue("BLOCKED", 1))
			Expect(res.ByQueryType).Should(HaveKeyWithValue("A", 1))
			Expect(res.ByQueryType).Should(HaveKeyWithValue("AAAA", 1))
			Expect(res.ByResponseCode).Should(HaveKeyWithValue("NOERROR", 1))
			Expect(res.ByResponseCode).Should(HaveKeyWithValue("NXDOMAIN", 1))
		})
	})

	Describe("windowing", func() {
		It("evicts buckets older than 24h", func() {
			clk := &fakeClock{t: mustParse("2026-06-08T00:30:00Z")}
			c := newCollectorWithClock(clk.now)

			c.Record(Sample{Disposition: DispositionAnswered, RType: "RESOLVED", QType: "A", Domain: "old.com"})

			clk.t = mustParse("2026-06-09T01:30:00Z") // > 24h later
			c.Record(Sample{Disposition: DispositionAnswered, RType: "RESOLVED", QType: "A", Domain: "new.com"})

			res := c.Snapshot()
			Expect(res.Summary.Queries).Should(Equal(1))
			Expect(res.ByResponseType).Should(HaveKeyWithValue("RESOLVED", 1))
			names := namesOf(res.TopDomains)
			Expect(names).Should(ContainElement("new.com"))
			Expect(names).ShouldNot(ContainElement("old.com"))
		})

		It("builds a per-hour series across buckets", func() {
			clk := &fakeClock{t: mustParse("2026-06-08T10:00:00Z")}
			c := newCollectorWithClock(clk.now)

			c.Record(Sample{Disposition: DispositionAnswered, RType: "BLOCKED", QType: "A", Domain: "ads.com", Blocked: true})
			clk.t = mustParse("2026-06-08T11:00:00Z")
			c.Record(Sample{Disposition: DispositionAnswered, RType: "RESOLVED", QType: "A", Domain: "ok.com"})

			res := c.Snapshot()
			Expect(res.PerHour).Should(HaveLen(2))

			total := 0
			blocked := 0
			for _, p := range res.PerHour {
				total += p.Queries
				blocked += p.Blocked
			}
			Expect(total).Should(Equal(2))
			Expect(blocked).Should(Equal(1))
		})

		It("prunes high-cardinality maps of closed buckets to keepPerHour", func() {
			clk := &fakeClock{t: mustParse("2026-06-08T10:00:00Z")}
			c := newCollectorWithClock(clk.now)

			for i := 0; i < keepPerHour+50; i++ {
				c.Record(Sample{
					Disposition: DispositionAnswered, RType: "RESOLVED", QType: "A",
					Domain: domainN(i), Client: "c1",
				})
			}
			// Roll to next hour: the previous bucket becomes closed and is pruned.
			clk.t = mustParse("2026-06-08T11:00:00Z")
			c.Record(Sample{Disposition: DispositionAnswered, RType: "RESOLVED", QType: "A", Domain: "trigger.com"})

			c.mu.RLock()
			defer c.mu.RUnlock()
			closed := c.buckets["2026060810"]
			Expect(len(closed.domains)).Should(Equal(keepPerHour))
		})

		It("caps the current bucket working set", func() {
			clk := &fakeClock{t: mustParse("2026-06-08T10:00:00Z")}
			c := newCollectorWithClock(clk.now)

			for i := 0; i < maxTrackedPerHour+10; i++ {
				c.Record(Sample{
					Disposition: DispositionAnswered, RType: "RESOLVED", QType: "A",
					Domain: domainN(i),
				})
			}

			c.mu.RLock()
			defer c.mu.RUnlock()
			cur := c.buckets["2026060810"]
			Expect(len(cur.domains)).Should(BeNumerically("<=", maxTrackedPerHour))
		})
	})

	Describe("point-in-time gauges", func() {
		It("tracks the latest cache entry count", func() {
			sut.SetCacheEntries(42)
			sut.SetCacheEntries(99)
			Expect(sut.Snapshot().CacheEntries).Should(Equal(99))
		})

		It("tracks per-group denylist and allowlist counts", func() {
			sut.SetDenylistCount("ads", 52000)
			sut.SetAllowlistCount("white", 12)

			res := sut.Snapshot()
			Expect(res.Lists.Denylist).Should(HaveKeyWithValue("ads", 52000))
			Expect(res.Lists.Allowlist).Should(HaveKeyWithValue("white", 12))
		})
	})
})

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time { return f.t }

func mustParse(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	Expect(err).Should(Succeed())
	return t
}

func namesOf(in []NameCount) []string {
	out := make([]string, 0, len(in))
	for _, nc := range in {
		out = append(out, nc.Name)
	}
	return out
}

func domainN(i int) string {
	return "d" + strconv.Itoa(i) + ".com"
}
