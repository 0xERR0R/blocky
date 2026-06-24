package cmd

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/0xERR0R/blocky/api"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

const (
	statsTimeFormat = "2006-01-02 15:04"
	emptyNote       = "(none)"
)

// renderStats writes a human-readable dashboard of the stats snapshot to w.
func renderStats(w io.Writer, s *api.ApiStats) {
	fmt.Fprintf(w, "Window: %s .. %s (UTC)\n\n",
		s.Start.UTC().Format(statsTimeFormat),
		s.End.UTC().Format(statsTimeFormat))

	renderSummary(w, s)
	renderTopTable(w, "Top Domains", s.TopDomains)
	renderTopTable(w, "Top Blocked", s.TopBlockedDomains)
	renderTopTable(w, "Top Clients", s.TopClients)
	renderBreakdown(w, "By Query Type", s.ByQueryType)
	renderBreakdown(w, "By Response Code", s.ByResponseCode)
	renderBreakdown(w, "By Response Type", s.ByResponseType)
	renderFooter(w, s)
}

func newStatsTable(w io.Writer, rightAlignCols ...int) table.Writer {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleLight)

	cfgs := make([]table.ColumnConfig, 0, len(rightAlignCols))
	for _, c := range rightAlignCols {
		cfgs = append(cfgs, table.ColumnConfig{Number: c, Align: text.AlignRight})
	}

	t.SetColumnConfigs(cfgs)

	return t
}

func renderSummary(w io.Writer, s *api.ApiStats) {
	sum := s.Summary

	fmt.Fprintf(w, "Summary\n")

	t := newStatsTable(w, 2)
	t.AppendHeader(table.Row{"Metric", "Value"})
	t.AppendRow(table.Row{"Queries", formatInt(sum.Queries)})
	t.AppendRow(table.Row{"Cached", withPercent(sum.Cached, sum.Queries)})
	t.AppendRow(table.Row{"Forwarded", formatInt(sum.Forwarded)})
	t.AppendRow(table.Row{"Blocked", withPercent(sum.Blocked, sum.Queries)})
	t.AppendRow(table.Row{"Local", formatInt(sum.Local)})
	t.AppendRow(table.Row{"Dropped", formatInt(sum.Dropped)})
	t.AppendRow(table.Row{"Errors", formatInt(sum.Errors)})
	t.AppendRow(table.Row{"Avg response", fmt.Sprintf("%d ms", sum.AvgResponseMs)})
	t.AppendRow(table.Row{"Cache hit rate", fmt.Sprintf("%.1f%%", sum.CacheHitRate*100)})
	t.Render()
	fmt.Fprintln(w)
}

func renderTopTable(w io.Writer, title string, rows []api.ApiNameCount) {
	if len(rows) == 0 {
		fmt.Fprintf(w, "%s: %s\n\n", title, emptyNote)

		return
	}

	fmt.Fprintf(w, "%s\n", title)

	t := newStatsTable(w, 2)
	t.AppendHeader(table.Row{"Name", "Count"})

	for _, r := range rows {
		t.AppendRow(table.Row{r.Name, formatInt(r.Count)})
	}

	t.Render()
	fmt.Fprintln(w)
}

func renderBreakdown(w io.Writer, title string, counts map[string]int) {
	if len(counts) == 0 {
		fmt.Fprintf(w, "%s: %s\n\n", title, emptyNote)

		return
	}

	type kv struct {
		name  string
		count int
	}

	items := make([]kv, 0, len(counts))
	for k, v := range counts {
		items = append(items, kv{k, v})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}

		return items[i].name < items[j].name
	})

	fmt.Fprintf(w, "%s\n", title)

	t := newStatsTable(w, 2)
	t.AppendHeader(table.Row{"Type", "Count"})

	for _, it := range items {
		t.AppendRow(table.Row{it.name, formatInt(it.count)})
	}

	t.Render()
	fmt.Fprintln(w)
}

func renderFooter(w io.Writer, s *api.ApiStats) {
	fmt.Fprintf(w, "Cache: %s entries\n\n", formatInt(s.Cache.Entries))

	groups := map[string]struct{}{}
	for g := range s.Lists.Denylist {
		groups[g] = struct{}{}
	}

	for g := range s.Lists.Allowlist {
		groups[g] = struct{}{}
	}

	if len(groups) == 0 {
		fmt.Fprintf(w, "Lists: %s\n", emptyNote)

		return
	}

	names := make([]string, 0, len(groups))
	for g := range groups {
		names = append(names, g)
	}

	sort.Strings(names)

	fmt.Fprintf(w, "Lists\n")

	t := newStatsTable(w, 2, 3)
	t.AppendHeader(table.Row{"Group", "Denylist", "Allowlist"})

	for _, g := range names {
		t.AppendRow(table.Row{g, formatInt(s.Lists.Denylist[g]), formatInt(s.Lists.Allowlist[g])})
	}

	t.Render()
	fmt.Fprintln(w)
}

func withPercent(part, total int) string {
	return fmt.Sprintf("%s (%s)", formatInt(part), formatPercent(part, total))
}

func formatPercent(part, total int) string {
	if total == 0 {
		return "0.0%"
	}

	return fmt.Sprintf("%.1f%%", float64(part)/float64(total)*100)
}

func formatInt(n int) string {
	s := strconv.Itoa(n)

	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}

	var b strings.Builder

	for i := range len(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}

		b.WriteByte(s[i])
	}

	if neg {
		return "-" + b.String()
	}

	return b.String()
}
