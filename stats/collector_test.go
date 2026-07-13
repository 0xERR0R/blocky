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

	answered := func(rtype, qtype, rcode, domain, client string) Sample {
		return Sample{
			Disposition: DispositionAnswered,
			RType:       rtype, QType: qtype, RCode: rcode,
			Domain: domain, Client: client, DurationMs: 10,
		}
	}

	Describe("summary", func() {
		It("classifies response types into curated categories", func() {
			sut.Record(answered("CACHED", "A", "NOERROR", "a.com", "c1"))
			sut.Record(answered("RESOLVED", "A", "NOERROR", "b.com", "c1"))
			sut.Record(answered("CONDITIONAL", "A", "NOERROR", "c.com", "c2"))
			sut.Record(answered("BLOCKED", "A", "NOERROR", "ads.com", "c2"))
			sut.Record(answered("FILTERED", "AAAA", "NOERROR", "d.com", "c2"))
			sut.Record(answered("NOTFQDN", "A", "NOERROR", "notfqdn.local", "c2"))
			sut.Record(answered("HOSTSFILE", "A", "NOERROR", "e.com", "c1"))
			sut.Record(Sample{Disposition: DispositionDropped, QType: "A", Domain: "x.com", Client: "c3", DurationMs: 1})
			sut.Record(Sample{Disposition: DispositionErrored, QType: "A", DurationMs: 2})

			res := sut.Snapshot()

			Expect(res.Summary.Cached).Should(Equal(1))
			Expect(res.Summary.Forwarded).Should(Equal(2)) // RESOLVED + CONDITIONAL
			Expect(res.Summary.Blocked).Should(Equal(1))   // BLOCKED only
			Expect(res.Summary.Filtered).Should(Equal(2))  // FILTERED + NOTFQDN
			Expect(res.Summary.Local).Should(Equal(1))     // HOSTSFILE
			Expect(res.Summary.Dropped).Should(Equal(1))
			Expect(res.Summary.Errors).Should(Equal(1))
			Expect(res.Summary.Queries).Should(Equal(9))
			// 7 answered queries × 10ms each / 7; drop (1ms) and error (2ms) latency is excluded.
			Expect(res.Summary.AvgResponseMs).Should(Equal(10))
		})

		It("counts only true blocks in Top Blocked, not query-type filtered responses", func() {
			sut.Record(answered("BLOCKED", "A", "NOERROR", "ads.com", "c1"))
			sut.Record(answered("FILTERED", "AAAA", "NOERROR", "example.com", "c1"))
			sut.Record(answered("NOTFQDN", "A", "NOERROR", "notfqdn.local", "c1"))

			names := namesOf(sut.Snapshot().TopBlockedDomains)
			Expect(names).Should(ContainElement("ads.com"))
			Expect(names).ShouldNot(ContainElement("example.com"))
			Expect(names).ShouldNot(ContainElement("notfqdn.local"))
		})

		It("counts rebinding-protection hits as blocked, not filtered", func() {
			sut.Record(answered("BLOCKED", "A", "NOERROR", "ads.com", "c1"))
			sut.Record(answered("REBIND", "A", "NOERROR", "rebind.example.com", "c1"))
			sut.Record(answered("FILTERED", "AAAA", "NOERROR", "example.com", "c1"))

			res := sut.Snapshot()

			Expect(res.Summary.Blocked).Should(Equal(2))  // BLOCKED + REBIND
			Expect(res.Summary.Filtered).Should(Equal(1)) // FILTERED only
			Expect(namesOf(res.TopBlockedDomains)).Should(ContainElement("rebind.example.com"))
		})

		It("counts DNSSEC validation failures as errors, not blocked", func() {
			sut.Record(answered("BLOCKED", "A", "NOERROR", "ads.com", "c1"))
			sut.Record(answered("BOGUS", "A", "SERVFAIL", "bogus.example.com", "c1"))
			sut.Record(Sample{Disposition: DispositionErrored, QType: "A", DurationMs: 2})

			res := sut.Snapshot()

			Expect(res.Summary.Blocked).Should(Equal(1)) // BLOCKED only
			Expect(res.Summary.Errors).Should(Equal(2))  // chain error + BOGUS
			// a domain with broken signatures is not something blocky blocked
			Expect(namesOf(res.TopBlockedDomains)).ShouldNot(ContainElement("bogus.example.com"))
			// still a query that reached an answer, so it counts in the total
			Expect(res.Summary.Queries).Should(Equal(3))
		})

		It("computes cacheHitRate as cached/(cached+forwarded)", func() {
			sut.Record(answered("CACHED", "A", "NOERROR", "a.com", "c1"))
			sut.Record(answered("CACHED", "A", "NOERROR", "a.com", "c1"))
			sut.Record(answered("RESOLVED", "A", "NOERROR", "b.com", "c1"))

			Expect(sut.Snapshot().Summary.CacheHitRate).Should(BeNumerically("~", 0.666, 0.01))
		})

		It("returns zero cacheHitRate when there are no cache lookups", func() {
			sut.Record(answered("BLOCKED", "A", "NOERROR", "ads.com", "c1"))

			Expect(sut.Snapshot().Summary.CacheHitRate).Should(Equal(0.0))
		})

		It("orders equal-count top entries alphabetically", func() {
			sut.Record(answered("RESOLVED", "A", "NOERROR", "bbb.com", "c1"))
			sut.Record(answered("RESOLVED", "A", "NOERROR", "aaa.com", "c1"))

			top := sut.Snapshot().TopDomains
			Expect(top).Should(HaveLen(2))
			Expect(top[0].Name).Should(Equal("aaa.com"))
			Expect(top[1].Name).Should(Equal("bbb.com"))
		})

		It("exposes raw byResponseType / byQueryType / byResponseCode", func() {
			sut.Record(answered("CACHED", "A", "NOERROR", "a.com", "c1"))
			sut.Record(answered("BLOCKED", "AAAA", "NXDOMAIN", "ads.com", "c1"))

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

			c.Record(Sample{Disposition: DispositionAnswered, RType: "BLOCKED", QType: "A", Domain: "ads.com"})
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

		It("counts only true blocks in the per-hour blocked series", func() {
			clk := &fakeClock{t: mustParse("2026-06-08T10:00:00Z")}
			c := newCollectorWithClock(clk.now)

			c.Record(Sample{Disposition: DispositionAnswered, RType: "BLOCKED", QType: "A", Domain: "ads.com"})
			c.Record(Sample{Disposition: DispositionAnswered, RType: "REBIND", QType: "A", Domain: "rebind.com"})
			c.Record(Sample{Disposition: DispositionAnswered, RType: "FILTERED", QType: "AAAA", Domain: "ok.com"})
			c.Record(Sample{Disposition: DispositionAnswered, RType: "NOTFQDN", QType: "A", Domain: "notfqdn"})

			res := c.Snapshot()

			Expect(res.PerHour).Should(HaveLen(1))
			Expect(res.PerHour[0].Queries).Should(Equal(4))
			// BLOCKED + REBIND; query-type filtered and NOTFQDN are not blocks.
			Expect(res.PerHour[0].Blocked).Should(Equal(2))
			// FILTERED + NOTFQDN keep their own series, so the volume the blocked
			// series no longer carries stays observable per hour.
			Expect(res.PerHour[0].Filtered).Should(Equal(2))
		})

		It("prunes high-cardinality maps of closed buckets to keepPerHour", func() {
			clk := &fakeClock{t: mustParse("2026-06-08T10:00:00Z")}
			c := newCollectorWithClock(clk.now)

			for i := range keepPerHour + 50 {
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
			Expect(closed.domains).Should(HaveLen(keepPerHour))
		})

		It("caps the current bucket working set", func() {
			clk := &fakeClock{t: mustParse("2026-06-08T10:00:00Z")}
			c := newCollectorWithClock(clk.now)

			for i := range maxTrackedPerHour + 10 {
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

	Describe("timestamp normalization", func() {
		It("reports start, end and per-hour timestamps in UTC regardless of the clock's zone", func() {
			ist := time.FixedZone("IST", 5*3600+1800) // +05:30, a sub-hour offset
			clk := &fakeClock{t: mustParse("2026-06-08T10:15:00Z").In(ist)}
			c := newCollectorWithClock(clk.now)

			c.Record(Sample{Disposition: DispositionAnswered, RType: "RESOLVED", QType: "A", Domain: "x.com"})

			res := c.Snapshot()
			Expect(res.Start.Location()).Should(Equal(time.UTC))
			Expect(res.End.Location()).Should(Equal(time.UTC))
			Expect(res.PerHour).Should(HaveLen(1))
			Expect(res.PerHour[0].Hour.Location()).Should(Equal(time.UTC))
			// 10:15Z truncates to the 10:00Z hour, not a 10:30 sub-hour boundary.
			Expect(res.PerHour[0].Hour).Should(BeTemporally("==", mustParse("2026-06-08T10:00:00Z")))
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
