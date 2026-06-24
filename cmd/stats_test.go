package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus/hooks/test"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func sampleStats() api.ApiStats {
	start := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)

	return api.ApiStats{
		Start: start,
		End:   start.Add(12 * time.Hour),
		Summary: api.ApiStatsSummary{
			Queries: 12431, Cached: 5102, Forwarded: 4445, Blocked: 2884,
			Local: 12, Dropped: 3, Errors: 7, AvgResponseMs: 7, CacheHitRate: 0.41,
		},
		ByQueryType:       map[string]int{"A": 9000, "AAAA": 3431},
		ByResponseCode:    map[string]int{"NOERROR": 11000, "NXDOMAIN": 1431},
		ByResponseType:    map[string]int{"CACHED": 5102, "BLOCKED": 2884},
		TopDomains:        []api.ApiNameCount{{Name: "github.com", Count: 1203}},
		TopBlockedDomains: []api.ApiNameCount{{Name: "ads.example.com", Count: 402}},
		TopClients:        []api.ApiNameCount{{Name: "10.0.0.5", Count: 4310}},
		Lists: api.ApiListCounts{
			Denylist:  map[string]int{"ads": 142000},
			Allowlist: map[string]int{"ads": 30},
		},
		Cache: api.ApiCacheStats{Entries: 8123},
	}
}

var _ = Describe("renderStats", func() {
	It("renders a populated snapshot with formatted numbers and all sections", func() {
		s := sampleStats()
		var buf bytes.Buffer

		renderStats(&buf, &s)
		out := buf.String()

		Expect(out).Should(ContainSubstring("Window:"))
		Expect(out).Should(ContainSubstring("(UTC)"))
		Expect(out).Should(ContainSubstring("Summary"))
		Expect(out).Should(ContainSubstring("Queries"))
		Expect(out).Should(ContainSubstring("12,431")) // thousands separator
		Expect(out).Should(ContainSubstring("41.0%"))  // cache hit rate 0.41 -> 41.0%
		Expect(out).Should(ContainSubstring("Top Domains"))
		Expect(out).Should(ContainSubstring("github.com"))
		Expect(out).Should(ContainSubstring("Top Blocked"))
		Expect(out).Should(ContainSubstring("ads.example.com"))
		Expect(out).Should(ContainSubstring("Top Clients"))
		Expect(out).Should(ContainSubstring("By Query Type"))
		Expect(out).Should(ContainSubstring("Cache: 8,123 entries"))
		Expect(out).Should(ContainSubstring("Lists"))
		Expect(out).Should(ContainSubstring("7 ms"))
		Expect(out).Should(ContainSubstring("By Response Code"))
		Expect(out).Should(ContainSubstring("By Response Type"))
		Expect(out).Should(ContainSubstring("142,000"))
		Expect(strings.Index(out, "9,000")).Should(BeNumerically("<", strings.Index(out, "3,431")))
	})

	It("renders (none) for empty lists and avoids divide-by-zero when there are no queries", func() {
		s := api.ApiStats{
			Start:          time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC),
			End:            time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC),
			Summary:        api.ApiStatsSummary{}, // all zero
			ByQueryType:    map[string]int{},
			ByResponseCode: map[string]int{},
			ByResponseType: map[string]int{},
			TopDomains:     []api.ApiNameCount{},
			Lists:          api.ApiListCounts{Denylist: map[string]int{}, Allowlist: map[string]int{}},
			Cache:          api.ApiCacheStats{Entries: 0},
		}
		var buf bytes.Buffer

		renderStats(&buf, &s)
		out := buf.String()

		Expect(out).Should(ContainSubstring("Top Domains: (none)"))
		Expect(out).Should(ContainSubstring("By Query Type: (none)"))
		Expect(out).Should(ContainSubstring("Lists: (none)"))
		Expect(out).Should(ContainSubstring("0.0%")) // no panic, graceful percentage
	})

	It("formats integers with thousands separators", func() {
		Expect(formatInt(0)).Should(Equal("0"))
		Expect(formatInt(999)).Should(Equal("999"))
		Expect(formatInt(12431)).Should(Equal("12,431"))
		Expect(formatInt(1000000)).Should(Equal("1,000,000"))
		Expect(formatInt(-12431)).Should(Equal("-12,431"))
	})

	It("formats percentages and guards against zero totals", func() {
		Expect(formatPercent(41, 100)).Should(Equal("41.0%"))
		Expect(formatPercent(0, 0)).Should(Equal("0.0%"))
	})
})

var _ = Describe("stats command", func() {
	var (
		ts         *httptest.Server
		mockFn     func(w http.ResponseWriter, _ *http.Request)
		loggerHook *test.Hook
	)

	JustBeforeEach(func() {
		ts = testHTTPAPIServer(mockFn)
	})
	JustAfterEach(func() {
		ts.Close()
	})
	BeforeEach(func() {
		mockFn = func(w http.ResponseWriter, _ *http.Request) {}
		loggerHook = test.NewGlobal()
		log.Log().AddHook(loggerHook)
	})
	AfterEach(func() {
		loggerHook.Reset()
	})

	When("stats are available", func() {
		BeforeEach(func() {
			mockFn = func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Content-Type", "application/json")
				s := sampleStats()
				response, err := json.Marshal(s)
				Expect(err).Should(Succeed())
				_, err = w.Write(response)
				Expect(err).Should(Succeed())
			}
		})
		It("renders the dashboard to the command output", func() {
			cmd := withContext(NewStatsCommand())
			var buf bytes.Buffer
			cmd.SetOut(&buf)

			Expect(stats(cmd, []string{})).Should(Succeed())
			Expect(buf.String()).Should(ContainSubstring("Queries"))
			Expect(buf.String()).Should(ContainSubstring("github.com"))
			Expect(buf.String()).Should(ContainSubstring("Cache:"))
		})
	})

	When("statistics are disabled (503)", func() {
		BeforeEach(func() {
			mockFn = func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("statistics are disabled"))
			}
		})
		It("returns a friendly error", func() {
			err := stats(withContext(NewStatsCommand()), []string{})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("disabled"))
		})
	})

	When("server returns 500", func() {
		BeforeEach(func() {
			mockFn = func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		It("returns an error", func() {
			err := stats(withContext(NewStatsCommand()), []string{})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("500 Internal Server Error"))
		})
	})

	When("the API URL is unreachable", func() {
		It("returns a transport error", func() {
			apiPort = 0
			err := stats(withContext(NewStatsCommand()), []string{})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("connection refused"))
		})
	})
})
