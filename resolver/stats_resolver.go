package resolver

import (
	"blocky/stats"
	"blocky/util"
	"fmt"
	"strings"

	"github.com/jedib0t/go-pretty/table"
	"github.com/miekg/dns"
)

// StatsResolver calculates query statistics
type StatsResolver struct {
	NextResolver
	recorders []*resolverStatRecorder
	statsChan chan *statsEntry
}

type statsEntry struct {
	request  *Request
	response *Response
}

type resolverStatRecorder struct {
	aggregator *stats.Aggregator
	fn         func(*statsEntry) string
}

func newRecorder(name string, fn func(*statsEntry) string) *resolverStatRecorder {
	return &resolverStatRecorder{
		aggregator: stats.NewAggregator(name),
		fn:         fn,
	}
}

func newRecorderWithMax(name string, max uint, fn func(*statsEntry) string) *resolverStatRecorder {
	return &resolverStatRecorder{
		aggregator: stats.NewAggregatorWithMax(name, max),
		fn:         fn,
	}
}

func (r *StatsResolver) collectStats() {
	for statsEntry := range r.statsChan {
		for _, rec := range r.recorders {
			rec.recordStats(statsEntry)
		}
	}
}

// Resolve calculates query statistics
func (r *StatsResolver) Resolve(request *Request) (*Response, error) {
	resp, err := r.next.Resolve(request)

	if err == nil {
		r.statsChan <- &statsEntry{
			request:  request,
			response: resp,
		}
	}

	return resp, err
}

// Configuration returns current configuraion
func (r *StatsResolver) Configuration() (result []string) {
	result = append(result, "stats:")
	for _, rec := range r.recorders {
		result = append(result, fmt.Sprintf(" - %s", rec.aggregator.Name))
	}

	return
}

func (r *resolverStatRecorder) recordStats(e *statsEntry) {
	r.aggregator.Put(r.fn(e))
}

// NewStatsResolver creates new instance of the resolver
func NewStatsResolver() ChainedResolver {
	resolver := &StatsResolver{
		statsChan: make(chan *statsEntry, 20),
		recorders: createRecorders(),
	}

	go resolver.collectStats()

	registerStatsTrigger(resolver)

	return resolver
}

func (r *StatsResolver) printStats() {
	logger := logger("stats_resolver")

	w := logger.Writer()
	defer w.Close()

	logger.Info("******* STATS 24h *******")

	for _, s := range r.recorders {
		t := table.NewWriter()
		t.SetOutputMirror(w)
		t.SetTitle(s.aggregator.Name)

		t.SetStyle(table.StyleLight)

		util.IterateValueSorted(s.aggregator.AggregateResult(), func(k string, v int) {
			t.AppendRow([]interface{}{fmt.Sprintf("%50s", k), v})
		})

		t.Render()
	}
}

func createRecorders() []*resolverStatRecorder {
	return []*resolverStatRecorder{
		newRecorderWithMax("Top 20 queries", 20, func(e *statsEntry) string {
			return util.ExtractDomain(e.request.Req.Question[0])
		}),
		newRecorderWithMax("Top 20 blocked queries", 20, func(e *statsEntry) string {
			if e.response.RType == BLOCKED {
				return util.ExtractDomain(e.request.Req.Question[0])
			}
			return ""
		}),
		newRecorder("Query count per client", func(e *statsEntry) string {
			return strings.Join(e.request.ClientNames, ",")
		}),
		newRecorder("Reason", func(e *statsEntry) string {
			return e.response.Reason
		}),
		newRecorder("Query type", func(e *statsEntry) string {
			return dns.TypeToString[e.request.Req.Question[0].Qtype]
		}),
		newRecorder("Response type", func(e *statsEntry) string {
			return dns.RcodeToString[e.response.Res.Rcode]
		}),
	}
}
