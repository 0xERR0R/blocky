package resolver

import (
	"fmt"
	"testing"
)

// benchSelectResolver is a distinct, comparable Resolver. The id field gives it a non-zero
// size so each &benchSelectResolver has a unique address — unlike the zero-size NoOpResolver,
// whose pointers all compare equal and would defeat the exclusion check.
type benchSelectResolver struct {
	NoOpResolver

	id int
}

// benchUpstreamStatuses builds n distinct, error-free resolver statuses. An unset
// lastErrorTime gives every status the full (equal) weight — the steady state.
func benchUpstreamStatuses(n int) []*upstreamResolverStatus {
	statuses := make([]*upstreamResolverStatus, 0, n)

	for i := range n {
		statuses = append(statuses, newUpstreamResolverStatus(&benchSelectResolver{id: i}))
	}

	return statuses
}

// BenchmarkParallelBestResolverSelection quantifies the Tier-4a fix: per-request resolver
// selection must not build a weightedrand.Chooser (choices slice + sort + totals alloc) on
// every call. pickRandom drives the parallel_best path (2 distinct resolvers); weightedRandom
// drives the random-strategy path (1 resolver).
//
//	go test -run=^$ -bench=BenchmarkParallelBestResolverSelection -benchmem ./resolver/
func BenchmarkParallelBestResolverSelection(b *testing.B) {
	for _, n := range []int{2, 5} {
		statuses := benchUpstreamStatuses(n)

		b.Run(fmt.Sprintf("pickRandom/upstreams=%d", n), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				_ = pickRandom(statuses, parallelBestResolverCount)
			}
		})

		b.Run(fmt.Sprintf("weightedRandom/upstreams=%d", n), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				_ = weightedRandom(statuses, nil)
			}
		})
	}
}
